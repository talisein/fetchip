#include <chrono>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>
#include <boost/ut.hpp>

#include "consensus_run.hpp"
#include "fetch_error.hpp"

using namespace std::literals;
using fip::AddressFamily;

struct thrown {};

struct scripted {
    std::chrono::milliseconds delay;
    std::variant<std::string, std::error_code, thrown> outcome;
};

struct fake_queries {
    fip::context& ctx;
    std::map<std::string_view, scripted> scripts;
    std::vector<std::string_view> launched;
    std::vector<std::string_view> completed;

    PublicIpQuery query()
    {
        return [this](Service service) { return answer(service); };
    }

    asio::awaitable<std::expected<std::string, std::error_code>> answer(Service service)
    {
        launched.push_back(service.address);
        const auto& script = scripts.at(service.address);
        asio::steady_timer timer {ctx.io_context, script.delay};
        co_await timer.async_wait(asio::use_awaitable);
        completed.push_back(service.address);
        if (const auto* text = std::get_if<std::string>(&script.outcome)) {
            co_return *text;
        }
        if (const auto* ec = std::get_if<std::error_code>(&script.outcome)) {
            co_return std::unexpected(*ec);
        }
        throw std::runtime_error("scripted failure");
    }
};

constexpr Service https(std::string_view address)
{
    return {address, address, "/", std::nullopt, ServiceType::HTTPS};
}

constexpr Service dns(std::string_view address, ServiceType type)
{
    return {address, address, std::nullopt, "resolver.example", type};
}

struct outcome {
    std::expected<std::string, std::error_code> result;
    std::vector<std::string_view> launched;
    std::vector<std::string_view> completed;
};

outcome run(std::vector<Service> candidates, std::map<std::string_view, scripted> scripts, AddressFamily family = AddressFamily::Any)
{
    fip::context ctx {39, true};
    ctx.requested_family = family;
    fake_queries fake {ctx, std::move(scripts), {}, {}};
    ConsensusRun consensus {ctx, std::move(candidates), fake.query()};
    auto result = consensus.run();
    return {std::move(result), fake.launched, fake.completed};
}

std::string describe(const outcome& o)
{
    return o.result ? *o.result : o.result.error().message();
}

int main() {
    using namespace boost::ut;

    "two agreeing answers win without a third"_test = [] {
        auto o = run({https("a"), https("b"), https("c")}, {
            {"a", {10ms, "192.0.2.1"s}},
            {"b", {10ms, "192.0.2.1"s}},
            {"c", {10ms, "192.0.2.1"s}},
        }, AddressFamily::V4);
        expect(o.result == "192.0.2.1"s) << describe(o);
        expect(o.launched == std::vector {"c"sv, "b"sv});
    };

    "an IPv4 answer keeps IPv6 topped up until a family wins"_test = [] {
        auto o = run({https("a"), https("b"), https("c")}, {
            {"a", {10s, "2001:db8::1"s}},
            {"b", {10ms, "192.0.2.1"s}},
            {"c", {20ms, "192.0.2.1"s}},
        });
        expect(o.result == "192.0.2.1"s) << describe(o);
        expect(o.launched == std::vector {"c"sv, "b"sv, "a"sv});
        expect(o.completed == std::vector {"b"sv, "c"sv});
    };

    "disagreement asks the next candidate"_test = [] {
        auto o = run({https("a"), https("b"), https("c")}, {
            {"a", {10ms, "192.0.2.1"s}},
            {"b", {20ms, "198.51.100.1"s}},
            {"c", {10ms, "192.0.2.1"s}},
        });
        expect(o.result == "192.0.2.1"s) << describe(o);
        expect(o.launched == std::vector {"c"sv, "b"sv, "a"sv});
    };

    "a thrown query is one lost vote"_test = [] {
        auto o = run({https("a"), https("b"), https("c")}, {
            {"a", {10ms, "192.0.2.1"s}},
            {"b", {20ms, "192.0.2.1"s}},
            {"c", {10ms, thrown {}}},
        });
        expect(o.result == "192.0.2.1"s) << describe(o);
        expect(o.launched == std::vector {"c"sv, "b"sv, "a"sv});
    };

    "a failed query is one lost vote"_test = [] {
        auto o = run({https("a"), https("b"), https("c")}, {
            {"a", {10ms, "192.0.2.1"s}},
            {"b", {20ms, "192.0.2.1"s}},
            {"c", {10ms, std::make_error_code(std::errc::connection_refused)}},
        });
        expect(o.result == "192.0.2.1"s) << describe(o);
        expect(o.launched == std::vector {"c"sv, "b"sv, "a"sv});
    };

    "an answer that is not an address is not a vote"_test = [] {
        auto o = run({https("a"), https("b"), https("c")}, {
            {"a", {10ms, "192.0.2.1"s}},
            {"b", {20ms, "192.0.2.1"s}},
            {"c", {10ms, "<html>"s}},
        });
        expect(o.result == "192.0.2.1"s) << describe(o);
        expect(o.launched == std::vector {"c"sv, "b"sv, "a"sv});
    };

    "running out of candidates is no consensus"_test = [] {
        auto o = run({https("a"), https("b")}, {
            {"a", {10ms, "192.0.2.1"s}},
            {"b", {10ms, "198.51.100.1"s}},
        });
        expect(o.result == std::unexpected(make_error_code(FetchError::NoConsensus))) << describe(o);
        expect(o.launched == std::vector {"b"sv, "a"sv});
    };

    "the first family to agree wins and cancels the rest"_test = [] {
        auto o = run({https("h"), dns("v6", ServiceType::DNS_AAAA), dns("v4", ServiceType::DNS_A)}, {
            {"h", {20ms, "192.0.2.1"s}},
            {"v6", {10s, "2001:db8::1"s}},
            {"v4", {10ms, "192.0.2.1"s}},
        });
        expect(o.result == "192.0.2.1"s) << describe(o);
        expect(o.launched == std::vector {"v4"sv, "h"sv, "v6"sv});
        expect(o.completed == std::vector {"v4"sv, "h"sv});
    };

    "a requested family only asks services that answer in it"_test = [] {
        auto o = run({https("h"), dns("v6", ServiceType::DNS_AAAA), dns("v4", ServiceType::DNS_A)}, {
            {"h", {10ms, "192.0.2.1"s}},
            {"v6", {10ms, "2001:db8::1"s}},
            {"v4", {10ms, "192.0.2.1"s}},
        }, AddressFamily::V4);
        expect(o.result == "192.0.2.1"s) << describe(o);
        expect(o.launched == std::vector {"v4"sv, "h"sv});
    };
}
