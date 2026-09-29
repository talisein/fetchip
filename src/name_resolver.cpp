#include <algorithm>
#include <limits>
#include <memory>
#include <string>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
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
    std::expected<Bytes, std::error_code> address_bytes(sd_json_variant* array)
    {
        Bytes bytes;
        if (!sd_json_variant_is_array(array) || sd_json_variant_elements(array) != bytes.size()) {
            return std::unexpected(std::make_error_code(std::errc::bad_message));
        }
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            auto* byte = sd_json_variant_by_index(array, i);
            if (!sd_json_variant_is_unsigned(byte) || sd_json_variant_unsigned(byte) > 0xff) {
                return std::unexpected(std::make_error_code(std::errc::bad_message));
            }
            bytes[i] = static_cast<unsigned char>(sd_json_variant_unsigned(byte));
        }
        return bytes;
    }

    std::expected<asio::ip::scope_id_type, std::error_code> interface_index(sd_json_variant* entry)
    {
        auto* ifindex = sd_json_variant_by_key(entry, "ifindex");
        if (!sd_json_variant_is_unsigned(ifindex)) {
            return std::unexpected(std::make_error_code(std::errc::bad_message));
        }
        if (sd_json_variant_unsigned(ifindex) > std::numeric_limits<asio::ip::scope_id_type>::max()) {
            return std::unexpected(std::make_error_code(std::errc::result_out_of_range));
        }
        return static_cast<asio::ip::scope_id_type>(sd_json_variant_unsigned(ifindex));
    }

    std::expected<asio::ip::address, std::error_code> parse_address(sd_json_variant* entry)
    {
        auto* family = sd_json_variant_by_key(entry, "family");
        auto* address = sd_json_variant_by_key(entry, "address");
        if (!sd_json_variant_is_integer(family)) {
            return std::unexpected(std::make_error_code(std::errc::bad_message));
        }
        switch (sd_json_variant_integer(family)) {
        case AF_INET:
            return address_bytes<asio::ip::address_v4::bytes_type>(address)
                .transform([](const auto& b) { return asio::ip::address {asio::ip::address_v4 {b}}; });
        case AF_INET6:
            return address_bytes<asio::ip::address_v6::bytes_type>(address)
                .and_then([&](const auto& b) -> std::expected<asio::ip::address, std::error_code> {
                    asio::ip::address_v6 v6 {b};
                    // A link-local address is unreachable without its interface.
                    if (v6.is_link_local()) {
                        auto scope = interface_index(entry);
                        if (!scope) {
                            return std::unexpected(scope.error());
                        }
                        v6.scope_id(*scope);
                    }
                    return asio::ip::address {v6};
                });
        default:
            return std::unexpected(std::make_error_code(std::errc::address_family_not_supported));
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
                    state.ctx.log.debug("Skipping a malformed address for {}: {}", state.host, address.error().message());
                }
            }
        }
        if (addresses.empty()) {
            state.ctx.log.debug("No addresses for {}", state.host);
            state.result = std::unexpected(make_error_code(FetchError::NameResolutionFailed));
            return 0;
        }
        // resolved lists the families in whatever order its transactions finished. IPv6 first is
        // what glibc's RFC 6724 sort gives on a native dual-stack host.
        std::ranges::stable_partition(addresses, &asio::ip::address::is_v6);
        state.result = std::move(addresses);
        return 0;
    }

    int lookup_family(fip::AddressFamily requested, fip::address_families (*configured_families)())
    {
        switch (requested) {
        case fip::AddressFamily::V4:
            return AF_INET;
        case fip::AddressFamily::V6:
            return AF_INET6;
        case fip::AddressFamily::Any:
            break;
        }
        // Like AI_ADDRCONFIG, don't return addresses of a family the host has no address in.
        const auto families = configured_families();
        if (families.v4 && !families.v6) {
            return AF_INET;
        }
        if (families.v6 && !families.v4) {
            return AF_INET6;
        }
        return AF_UNSPEC;
    }
}

fip::address_families fip::configured_address_families()
{
    ifaddrs* list = nullptr;
    if (::getifaddrs(&list) < 0) {
        return {.v4 = true, .v6 = true};
    }
    std::unique_ptr<ifaddrs, decltype(&::freeifaddrs)> owner {list, ::freeifaddrs};

    // Unlike glibc, IPv6 link-local addresses don't count: nearly every interface has one, so an
    // IPv4-only host would pass for dual-stack.
    const auto v4_link_local = asio::ip::make_network_v4("169.254.0.0/16").hosts();
    address_families families;
    for (auto* i = list; i; i = i->ifa_next) {
        if (!i->ifa_addr) {
            continue;
        }
        if (i->ifa_addr->sa_family == AF_INET) {
            const auto a = asio::ip::address_v4 {ntohl(reinterpret_cast<const sockaddr_in*>(i->ifa_addr)->sin_addr.s_addr)};
            if (!a.is_loopback() && v4_link_local.find(a) == v4_link_local.end()) {
                families.v4 = true;
            }
        } else if (i->ifa_addr->sa_family == AF_INET6) {
            asio::ip::address_v6::bytes_type bytes;
            std::ranges::copy(reinterpret_cast<const sockaddr_in6*>(i->ifa_addr)->sin6_addr.s6_addr, bytes.begin());
            const auto a = asio::ip::address_v6 {bytes};
            if (!a.is_loopback() && !a.is_link_local()) {
                families.v6 = true;
            }
        }
    }
    return families;
}

asio::awaitable<std::expected<std::vector<asio::ip::address>, std::error_code>>
resolve_host(fip::context& ctx, std::string_view host, std::chrono::steady_clock::duration timeout, std::string_view address,
             fip::address_families (*configured_families)())
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

    const int family = lookup_family(ctx.requested_family, configured_families);
    r = sd_varlink_invokebo(link.get(), "io.systemd.Resolve.ResolveHostname",
                            SD_JSON_BUILD_PAIR_STRING("name", state.host.c_str()),
                            SD_JSON_BUILD_PAIR_CONDITION(family != AF_UNSPEC, "family", SD_JSON_BUILD_INTEGER(family)));
    if (r < 0) {
        ctx.log.debug("Failed to send the lookup for {}: {}", host, errno_code(r).message());
        co_return std::unexpected(errno_code(r));
    }

    const int fd = sd_varlink_get_fd(link.get());
    if (fd < 0) {
        co_return std::unexpected(errno_code(fd));
    }
    // A duplicate, so the descriptor and the link each close their own.
    const int dup_fd = ::fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (dup_fd < 0) {
        co_return std::unexpected(std::error_code(errno, std::system_category()));
    }
    asio::posix::stream_descriptor descriptor {ctx.io_context};
    boost::system::error_code assign_error;
    descriptor.assign(dup_fd, assign_error);
    if (assign_error != boost::system::error_code {}) {
        ::close(dup_fd);
        ctx.log.debug("Failed to watch the lookup of {}: {}", host, assign_error.message());
        co_return std::unexpected(assign_error);
    }

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
        if (ec != boost::system::error_code {}) {
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
