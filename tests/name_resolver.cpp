#include <chrono>
#include <optional>
#include <string>
#include <vector>
#include <unistd.h>
#include <boost/ut.hpp>

#include "context.hpp"
#include "fetch_error.hpp"
#include "name_resolver.hpp"

using namespace std::literals;
using local = asio::local::stream_protocol;

struct outcome {
    std::expected<std::vector<asio::ip::address>, std::error_code> result;
    std::string request;
    std::chrono::steady_clock::duration elapsed;
};

struct lookup_options {
    std::optional<std::string> reply;
    fip::AddressFamily family = fip::AddressFamily::Any;
    fip::address_families (*configured_families)() = [] { return fip::address_families {.v4 = true, .v6 = true}; };
    std::chrono::steady_clock::duration timeout = 1s;
    std::optional<std::chrono::steady_clock::duration> cancel_after;
    bool serve = true;
};

std::string describe(const outcome& o)
{
    return o.result ? std::format("{} addresses", o.result->size()) : o.result.error().message();
}

// An abstract socket name, which sd-varlink spells with a leading '@' and asio with a leading NUL.
std::string socket_name()
{
    static int counter = 0;
    return std::format("fetchip-test-{}-{}", ::getpid(), counter++);
}

asio::awaitable<void> fake_resolved(local::acceptor& acceptor, std::optional<std::string> reply, std::string& request)
{
    auto socket = co_await acceptor.async_accept(asio::use_awaitable);
    acceptor.close();
    auto [ec, n] = co_await asio::async_read_until(socket, asio::dynamic_buffer(request), '\0', asio::as_tuple(asio::use_awaitable));
    if (ec != boost::system::error_code {}) {
        co_return;
    }
    if (reply) {
        std::string message = *reply;
        message.push_back('\0');
        co_await asio::async_write(socket, asio::buffer(message), asio::as_tuple(asio::use_awaitable));
    }
    // Hold the connection until the client hangs up.
    std::string rest;
    co_await asio::async_read(socket, asio::dynamic_buffer(rest), asio::as_tuple(asio::use_awaitable));
}

outcome lookup(const lookup_options& options)
{
    fip::context ctx {39, true};
    ctx.requested_family = options.family;
    const auto name = socket_name();
    const auto address = '@' + name;

    std::optional<local::acceptor> acceptor;
    std::string request;
    if (options.serve) {
        acceptor.emplace(ctx.io_context, local::endpoint('\0' + name));
        asio::co_spawn(ctx.io_context, fake_resolved(*acceptor, options.reply, request), asio::detached);
    }

    std::optional<std::expected<std::vector<asio::ip::address>, std::error_code>> result;
    asio::cancellation_signal cancel;
    asio::steady_timer cancel_timer {ctx.io_context};
    if (options.cancel_after) {
        cancel_timer.expires_after(*options.cancel_after);
        cancel_timer.async_wait([&](auto) { cancel.emit(asio::cancellation_type::terminal); });
    }

    const auto start = std::chrono::steady_clock::now();
    asio::co_spawn(ctx.io_context, resolve_host(ctx, "example.com", options.timeout, address, options.configured_families),
                   asio::bind_cancellation_slot(cancel.slot(),
                   [&](std::exception_ptr e, std::expected<std::vector<asio::ip::address>, std::error_code> r) {
                       cancel_timer.cancel();
                       if (acceptor) {
                           acceptor->close();
                       }
                       if (e) {
                           try { std::rethrow_exception(e); }
                           catch (const boost::system::system_error& ex) { result = std::unexpected(ex.code()); }
                       } else {
                           result = std::move(r);
                       }
                   }));
    ctx.io_context.run();
    const auto elapsed = std::chrono::steady_clock::now() - start;
    return {result.value(), request, elapsed};
}

int main() {
    using namespace boost::ut;

    "answers become addresses"_test = [] {
        auto o = lookup({.reply = R"({"parameters":{"addresses":[{"ifindex":1,"family":2,"address":[192,0,2,1]},{"family":10,"address":[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1]}],"name":"example.com","flags":0}})"});
        expect(fatal(o.result.has_value())) << describe(o);
        expect(o.result->size() == 2u);
        expect(o.result->at(0) == asio::ip::make_address("2001:db8::1"));
        expect(o.result->at(1) == asio::ip::make_address("192.0.2.1"));
        expect(o.request.contains(R"("method":"io.systemd.Resolve.ResolveHostname")")) << o.request;
        expect(o.request.contains(R"("name":"example.com")")) << o.request;
        expect(!o.request.contains("family")) << o.request;
    };

    "IPv6 addresses come first, each family in resolved's order"_test = [] {
        auto o = lookup({.reply = R"({"parameters":{"addresses":[{"family":2,"address":[192,0,2,1]},{"family":10,"address":[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1]},{"family":2,"address":[198,51,100,7]},{"family":10,"address":[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,2]}]}})"});
        expect(fatal(o.result.has_value())) << describe(o);
        expect(fatal(o.result->size() == 4u));
        expect(o.result->at(0) == asio::ip::make_address("2001:db8::1"));
        expect(o.result->at(1) == asio::ip::make_address("2001:db8::2"));
        expect(o.result->at(2) == asio::ip::make_address("192.0.2.1"));
        expect(o.result->at(3) == asio::ip::make_address("198.51.100.7"));
    };

    "requested family is passed on"_test = [] {
        const auto v6_only = [] { return fip::address_families {.v4 = false, .v6 = true}; };
        auto v4 = lookup({.reply = R"({"parameters":{"addresses":[{"family":2,"address":[192,0,2,1]}]}})", .family = fip::AddressFamily::V4, .configured_families = v6_only});
        expect(v4.request.contains(R"("family":2)")) << v4.request;
        const auto v4_only = [] { return fip::address_families {.v4 = true, .v6 = false}; };
        auto v6 = lookup({.reply = R"({"parameters":{"addresses":[{"family":10,"address":[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1]}]}})", .family = fip::AddressFamily::V6, .configured_families = v4_only});
        expect(v6.request.contains(R"("family":10)")) << v6.request;
    };

    "without a requested family, only configured families are asked for"_test = [] {
        auto v4 = lookup({.reply = R"({"parameters":{"addresses":[{"family":2,"address":[192,0,2,1]}]}})",
                          .configured_families = [] { return fip::address_families {.v4 = true, .v6 = false}; }});
        expect(v4.request.contains(R"("family":2)")) << v4.request;
        auto v6 = lookup({.reply = R"({"parameters":{"addresses":[{"family":10,"address":[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1]}]}})",
                          .configured_families = [] { return fip::address_families {.v4 = false, .v6 = true}; }});
        expect(v6.request.contains(R"("family":10)")) << v6.request;
        auto neither = lookup({.reply = R"({"parameters":{"addresses":[{"family":2,"address":[192,0,2,1]}]}})",
                               .configured_families = [] { return fip::address_families {}; }});
        expect(!neither.request.contains("family")) << neither.request;
        expect(neither.result.has_value()) << describe(neither);
    };

    "link-local IPv6 addresses carry their interface"_test = [] {
        auto o = lookup({.reply = R"({"parameters":{"addresses":[{"ifindex":3,"family":10,"address":[254,128,0,0,0,0,0,0,0,0,0,0,0,0,0,1]},{"ifindex":3,"family":10,"address":[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1]}]}})"});
        expect(fatal(o.result.has_value())) << describe(o);
        expect(fatal(o.result->size() == 2u));
        expect(o.result->at(0) == asio::ip::make_address("fe80::1%3")) << o.result->at(0).to_string();
        expect(o.result->at(0).to_v6().scope_id() == 3u);
        expect(o.result->at(1).to_v6().scope_id() == 0u);
    };

    "link-local IPv6 addresses without a usable interface are skipped"_test = [] {
        auto o = lookup({.reply = R"({"parameters":{"addresses":[{"family":10,"address":[254,128,0,0,0,0,0,0,0,0,0,0,0,0,0,2]},{"ifindex":-1,"family":10,"address":[254,128,0,0,0,0,0,0,0,0,0,0,0,0,0,3]},{"ifindex":4294967296,"family":10,"address":[254,128,0,0,0,0,0,0,0,0,0,0,0,0,0,4]},{"ifindex":3,"family":10,"address":[254,128,0,0,0,0,0,0,0,0,0,0,0,0,0,5]}]}})"});
        expect(fatal(o.result.has_value())) << describe(o);
        expect(fatal(o.result->size() == 1u));
        expect(o.result->at(0) == asio::ip::make_address("fe80::5%3")) << o.result->at(0).to_string();
    };

    "error replies fail the lookup"_test = [] {
        auto o = lookup({.reply = R"({"error":"io.systemd.Resolve.NoSuchResourceRecord","parameters":{}})"});
        expect(fatal(!o.result.has_value()));
        expect(o.result.error() == make_error_code(FetchError::NameResolutionFailed)) << describe(o);
    };

    "malformed addresses are skipped"_test = [] {
        auto o = lookup({.reply = R"({"parameters":{"addresses":[{"family":2,"address":[192,0,2]},{"family":2,"address":[192,0,2,256]},{"family":7,"address":[1,2,3,4]},{"family":2,"address":[198,51,100,7]}]}})"});
        expect(fatal(o.result.has_value())) << describe(o);
        expect(o.result->size() == 1u);
        expect(o.result->at(0) == asio::ip::make_address("198.51.100.7"));
    };

    "no usable addresses fail the lookup"_test = [] (std::string reply) {
        auto o = lookup({.reply = reply});
        expect(fatal(!o.result.has_value()));
        expect(o.result.error() == make_error_code(FetchError::NameResolutionFailed)) << describe(o);
    } | std::vector<std::string> {
        R"({"parameters":{}})",
        R"({"parameters":{"addresses":[]}})",
        R"({"parameters":{"addresses":[{"family":2,"address":[1,2,3]}]}})",
    };

    "a silent resolved times out"_test = [] {
        auto o = lookup({.timeout = 200ms});
        expect(fatal(!o.result.has_value()));
        expect(o.result.error() == std::make_error_code(std::errc::timed_out)) << describe(o);
        expect(o.elapsed >= 200ms);
        expect(o.elapsed < 1s) << std::chrono::duration_cast<std::chrono::milliseconds>(o.elapsed);
    };

    "cancellation ends the lookup promptly"_test = [] {
        auto o = lookup({.timeout = 5s, .cancel_after = 50ms});
        expect(fatal(!o.result.has_value()));
        expect(o.result.error() == std::errc::operation_canceled) << describe(o);
        expect(o.elapsed < 1s) << std::chrono::duration_cast<std::chrono::milliseconds>(o.elapsed);
    };

    "a missing resolved fails at once"_test = [] {
        auto o = lookup({.serve = false});
        expect(fatal(!o.result.has_value()));
        expect(o.elapsed < 1s) << std::chrono::duration_cast<std::chrono::milliseconds>(o.elapsed);
    };
}
