#include <memory>
#include <string>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>

#include "fetch_error.hpp"
#include "name_resolver.hpp"

namespace {
    struct varlink_close_unref {
        void operator()(sd_varlink* link) const { sd_varlink_close_unref(link); }
    };

    struct lookup {
        fip::context& ctx;
        std::string host;
        std::optional<std::expected<std::vector<asio::ip::address>, std::error_code>> result;
    };

    std::error_code errno_code(int r)
    {
        return {-r, std::system_category()};
    }

    template<class Bytes>
    std::optional<Bytes> address_bytes(sd_json_variant* array)
    {
        Bytes bytes;
        if (!sd_json_variant_is_array(array) || sd_json_variant_elements(array) != bytes.size()) {
            return std::nullopt;
        }
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            auto* byte = sd_json_variant_by_index(array, i);
            if (!sd_json_variant_is_unsigned(byte) || sd_json_variant_unsigned(byte) > 0xff) {
                return std::nullopt;
            }
            bytes[i] = static_cast<unsigned char>(sd_json_variant_unsigned(byte));
        }
        return bytes;
    }

    std::optional<asio::ip::address> parse_address(sd_json_variant* entry)
    {
        auto* family = sd_json_variant_by_key(entry, "family");
        auto* address = sd_json_variant_by_key(entry, "address");
        if (!sd_json_variant_is_integer(family)) {
            return std::nullopt;
        }
        switch (sd_json_variant_integer(family)) {
        case AF_INET:
            return address_bytes<asio::ip::address_v4::bytes_type>(address)
                .transform([](const auto& b) { return asio::ip::address {asio::ip::address_v4 {b}}; });
        case AF_INET6:
            return address_bytes<asio::ip::address_v6::bytes_type>(address)
                .transform([](const auto& b) { return asio::ip::address {asio::ip::address_v6 {b}}; });
        default:
            return std::nullopt;
        }
    }

    int on_reply(sd_varlink*, sd_json_variant* parameters, const char* error_id, sd_varlink_reply_flags_t, void* userdata)
    {
        auto& state = *static_cast<lookup*>(userdata);
        if (error_id) {
            state.ctx.log.debug("Failed to resolve {}: {}", state.host, error_id);
            state.result = std::unexpected(make_error_code(FetchError::NameResolutionFailed));
            return 0;
        }

        std::vector<asio::ip::address> addresses;
        auto* entries = sd_json_variant_by_key(parameters, "addresses");
        if (sd_json_variant_is_array(entries)) {
            for (std::size_t i = 0; i < sd_json_variant_elements(entries); ++i) {
                if (auto address = parse_address(sd_json_variant_by_index(entries, i))) {
                    addresses.push_back(*address);
                } else {
                    state.ctx.log.debug("Skipping a malformed address for {}", state.host);
                }
            }
        }
        if (addresses.empty()) {
            state.ctx.log.debug("No addresses for {}", state.host);
            state.result = std::unexpected(make_error_code(FetchError::NameResolutionFailed));
            return 0;
        }
        state.result = std::move(addresses);
        return 0;
    }
}

asio::awaitable<std::expected<std::vector<asio::ip::address>, std::error_code>>
resolve_host(fip::context& ctx, std::string_view host, std::chrono::steady_clock::duration timeout, std::string_view address)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    lookup state {ctx, std::string(host), std::nullopt};

    sd_varlink* raw = nullptr;
    int r = sd_varlink_connect_address(&raw, std::string(address).c_str());
    if (r < 0) {
        ctx.log.debug("Failed to connect to {}: {}", address, errno_code(r).message());
        co_return std::unexpected(errno_code(r));
    }
    std::unique_ptr<sd_varlink, varlink_close_unref> link {raw};
    sd_varlink_set_userdata(link.get(), &state);
    sd_varlink_bind_reply(link.get(), on_reply);

    switch (ctx.requested_family) {
    case fip::AddressFamily::V4:
        r = sd_varlink_invokebo(link.get(), "io.systemd.Resolve.ResolveHostname",
                                SD_JSON_BUILD_PAIR_STRING("name", state.host.c_str()),
                                SD_JSON_BUILD_PAIR_INTEGER("family", AF_INET));
        break;
    case fip::AddressFamily::V6:
        r = sd_varlink_invokebo(link.get(), "io.systemd.Resolve.ResolveHostname",
                                SD_JSON_BUILD_PAIR_STRING("name", state.host.c_str()),
                                SD_JSON_BUILD_PAIR_INTEGER("family", AF_INET6));
        break;
    case fip::AddressFamily::Any:
        r = sd_varlink_invokebo(link.get(), "io.systemd.Resolve.ResolveHostname",
                                SD_JSON_BUILD_PAIR_STRING("name", state.host.c_str()));
        break;
    }
    if (r < 0) {
        ctx.log.debug("Failed to send the lookup for {}: {}", host, errno_code(r).message());
        co_return std::unexpected(errno_code(r));
    }

    const int fd = sd_varlink_get_fd(link.get());
    if (fd < 0) {
        co_return std::unexpected(errno_code(fd));
    }
    // A duplicate, so the descriptor and the link each close their own.
    const int dup_fd = ::dup(fd);
    if (dup_fd < 0) {
        co_return std::unexpected(std::error_code(errno, std::system_category()));
    }
    asio::posix::stream_descriptor descriptor {ctx.io_context, dup_fd};

    while (true) {
        do {
            r = sd_varlink_process(link.get());
        } while (r > 0 && !state.result);
        if (r < 0) {
            ctx.log.debug("Lookup of {} failed: {}", host, errno_code(r).message());
            co_return std::unexpected(errno_code(r));
        }
        if (state.result) {
            co_return std::move(*state.result);
        }

        const int events = sd_varlink_get_events(link.get());
        if (events < 0) {
            co_return std::unexpected(errno_code(events));
        }
        const auto wait = (events & POLLOUT) ? asio::posix::descriptor_base::wait_write : asio::posix::descriptor_base::wait_read;
        const auto remaining = std::max(deadline - std::chrono::steady_clock::now(), std::chrono::steady_clock::duration::zero());
        auto [ec] = co_await descriptor.async_wait(wait, asio::cancel_after(remaining, asio::as_tuple(asio::use_awaitable)));
        if (ec) {
            // operation_aborted is the timeout only if the caller did not cancel the lookup.
            const auto cancelled = (co_await asio::this_coro::cancellation_state).cancelled();
            if (ec == asio::error::operation_aborted && cancelled == asio::cancellation_type::none) {
                ctx.log.debug("No address for {} within {}", host, std::chrono::duration_cast<std::chrono::milliseconds>(timeout));
                co_return std::unexpected(std::make_error_code(std::errc::timed_out));
            }
            ctx.log.debug("Lookup of {} failed: {}", host, ec.message());
            co_return std::unexpected(ec);
        }
    }
}
