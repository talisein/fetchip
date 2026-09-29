#pragma once

#include <chrono>
#include <expected>
#include <string_view>
#include <system_error>
#include <vector>

#include "context.hpp"

namespace fip
{
    constexpr std::string_view resolved_address = "/run/systemd/resolve/io.systemd.Resolve";

    // Whether the host has a non-loopback, non-link-local address in each family.
    struct address_families {
        bool v4 = false;
        bool v6 = false;
    };

    address_families configured_address_families();
}

asio::awaitable<std::expected<std::vector<asio::ip::address>, std::error_code>>
resolve_host(fip::context& ctx, std::string_view host,
             std::chrono::steady_clock::duration timeout = fip::name_resolution_timeout,
             std::string_view address = fip::resolved_address,
             fip::address_families (*configured_families)() = fip::configured_address_families);
