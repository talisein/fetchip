#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

#include <chrono>
#include <string_view>

namespace asio = boost::asio;
namespace beast = boost::beast;

namespace fip
{
    constexpr std::string_view user_agent = "fetchip";

    constexpr std::chrono::seconds name_resolution_timeout {3};
    constexpr std::chrono::seconds dns_resolution_timeout {2};
    constexpr std::chrono::seconds http_execution_timeout {5};
    constexpr std::chrono::seconds connection_shutdown_timeout {1};
}
