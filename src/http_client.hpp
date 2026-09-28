#pragma once

#include <expected>
#include <string>
#include <string_view>
#include <system_error>

#include "context.hpp"

// The body of a GET for path on url, where url is http://host or https://host.
asio::awaitable<std::expected<std::string, std::error_code>>
http_get(fip::context& ctx, std::string_view url, std::string_view path);
