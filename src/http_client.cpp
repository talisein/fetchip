#include <openssl/err.h>
#include <openssl/ssl.h>

#include "http_client.hpp"
#include "http_error.hpp"

namespace http = beast::http;
using asio::ip::tcp;

namespace {
    constexpr auto token = asio::as_tuple(asio::use_awaitable);
    constexpr std::size_t body_limit = 4096;
    // Beast encodes the version as major * 10 + minor.
    constexpr unsigned http_1_1 = 11;

    asio::awaitable<std::expected<tcp::resolver::results_type, std::error_code>>
    resolve(fip::context& ctx, std::string_view host, std::string_view port)
    {
        tcp::resolver resolver {ctx.io_context};
        boost::system::error_code ec;
        tcp::resolver::results_type result;
        switch (ctx.requested_family) {
        case fip::AddressFamily::V4:
            std::tie(ec, result) = co_await resolver.async_resolve(tcp::v4(), host, port, token);
            break;
        case fip::AddressFamily::V6:
            std::tie(ec, result) = co_await resolver.async_resolve(tcp::v6(), host, port, token);
            break;
        case fip::AddressFamily::Any:
            std::tie(ec, result) = co_await resolver.async_resolve(host, port, token);
            break;
        }
        if (ec) {
            ctx.log.debug("Failed to resolve {}: {}", host, ec.message());
            co_return std::unexpected(ec);
        }
        co_return result;
    }

    template<class Stream>
    asio::awaitable<std::expected<std::string, std::error_code>>
    exchange(fip::context& ctx, Stream& stream, std::string_view host, std::string_view path)
    {
        http::request<http::empty_body> req {http::verb::get, path, http_1_1};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, fip::user_agent);

        auto [write_ec, bytes_written] = co_await http::async_write(stream, req, token);
        if (write_ec) {
            ctx.log.debug("Failed to send request to {}: {}", host, write_ec.message());
            co_return std::unexpected(write_ec);
        }

        beast::flat_buffer buf;
        http::response_parser<http::string_body> parser;
        parser.body_limit(body_limit);
        auto [read_ec, bytes_read] = co_await http::async_read(stream, buf, parser, token);
        if (read_ec) {
            ctx.log.debug("Failed to read response from {}: {}", host, read_ec.message());
            co_return std::unexpected(read_ec);
        }

        auto res = parser.release();
        if (res.result() != http::status::ok) {
            ctx.log.debug("{} answered HTTP {}", host, res.result_int());
            co_return std::unexpected(make_error_code(HTTPError::UnexpectedStatus));
        }
        co_return std::move(res.body());
    }

    // The range connect only returns the last endpoint's error, so each failure is logged as it happens.
    asio::awaitable<std::expected<void, std::error_code>>
    connect(fip::context& ctx, beast::tcp_stream& stream, std::string_view host, const tcp::resolver::results_type& endpoints)
    {
        std::optional<tcp::endpoint> attempted;
        // Called before every attempt with the previous attempt's result; before the first, ec is always success.
        auto connect_condition_log_previous_endpoint_failure = [&](const boost::system::error_code& ec, const tcp::endpoint& next) {
            if (ec && attempted) {
                ctx.log.debug("Failed to connect to {} at {}: {}", host, attempted->address().to_string(), ec.message());
            }
            attempted = next;
            return true;
        };

        // One deadline for the whole exchange: connect, handshake, write and read on this stream.
        stream.expires_after(fip::http_execution_timeout);
        auto [ec, ep] = co_await stream.async_connect(endpoints, connect_condition_log_previous_endpoint_failure, token);
        if (ec) {
            // No condition call follows the last attempt.
            if (attempted) {
                ctx.log.debug("Failed to connect to {} at {}: {}", host, attempted->address().to_string(), ec.message());
            }
            co_return std::unexpected(ec);
        }
        ctx.log.debug("Connected to {}", ep.address().to_string());
        co_return std::expected<void, std::error_code> {};
    }
}

asio::awaitable<std::expected<std::string, std::error_code>>
http_get(fip::context& ctx, std::string_view url, std::string_view path)
{
    using namespace std::literals;
    bool secure;
    std::string_view host;
    if (url.starts_with("https://"sv)) {
        secure = true;
        host = url.substr("https://"sv.size());
    } else if (url.starts_with("http://"sv)) {
        secure = false;
        host = url.substr("http://"sv.size());
    } else {
        ctx.log.debug("Unsupported scheme in {}", url);
        co_return std::unexpected(make_error_code(HTTPError::UnsupportedScheme));
    }

    auto endpoints = co_await resolve(ctx, host, secure ? "https"sv : "http"sv);
    if (!endpoints) {
        co_return std::unexpected(endpoints.error());
    }

    if (!secure) {
        beast::tcp_stream stream {ctx.io_context};
        auto connected = co_await connect(ctx, stream, host, *endpoints);
        if (!connected) {
            co_return std::unexpected(connected.error());
        }
        auto body = co_await exchange(ctx, stream, host, path);
        boost::system::error_code ignored;
        stream.socket().shutdown(tcp::socket::shutdown_both, ignored);
        co_return body;
    }

    const std::string host_name {host};
    asio::ssl::stream<beast::tcp_stream> stream {ctx.io_context, ctx.ssl_context};
    // Neither asio nor beast sends SNI on their own.
    if (!SSL_set_tlsext_host_name(stream.native_handle(), host_name.c_str())) {
        boost::system::error_code ec {static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category()};
        ctx.log.debug("Failed to set SNI for {}: {}", host, ec.message());
        co_return std::unexpected(ec);
    }
    stream.set_verify_callback(asio::ssl::host_name_verification(host_name));

    auto connected = co_await connect(ctx, beast::get_lowest_layer(stream), host, *endpoints);
    if (!connected) {
        co_return std::unexpected(connected.error());
    }

    auto [handshake_ec] = co_await stream.async_handshake(asio::ssl::stream_base::client, token);
    if (handshake_ec) {
        ctx.log.debug("TLS handshake with {} failed: {}", host, handshake_ec.message());
        co_return std::unexpected(handshake_ec);
    }

    auto body = co_await exchange(ctx, stream, host, path);

    // The body stands whatever the shutdown does; eof and stream_truncated are a server skipping its close_notify.
    beast::get_lowest_layer(stream).expires_after(fip::connection_shutdown_timeout);
    auto [shutdown_ec] = co_await stream.async_shutdown(token);
    if (shutdown_ec && shutdown_ec != asio::error::eof && shutdown_ec != asio::ssl::error::stream_truncated) {
        ctx.log.debug("TLS shutdown with {} failed: {}", host, shutdown_ec.message());
    }
    co_return body;
}
