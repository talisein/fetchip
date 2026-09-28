#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

#include <string_view>

namespace asio = boost::asio;
namespace beast = boost::beast;

namespace fip
{
    constexpr std::string_view user_agent = "fetchip";
}
