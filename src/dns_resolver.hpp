#pragma once

#include <system_error>
#include <expected>

#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>
#include <asio/streambuf.hpp>

#include "context.hpp"

class DNSResolver
{
public:
    DNSResolver(fip::context &ctx) : ctx(ctx) { };

    std::expected<std::string, std::error_code>
    query_dns_public_ip(std::string_view host, std::string_view resolver);

private:
    std::expected<asio::ip::basic_resolver<asio::ip::udp>::results_type, asio::error_code>
    get_resolver_address(std::string_view resolver);

    std::expected<asio::ip::udp::socket, asio::error_code>
    create_socket_and_connect(const asio::ip::udp::endpoint& ep);

    std::expected<void, std::error_code>
    send_dns_query(asio::ip::udp::socket& sock, std::string_view host);

    std::expected<std::string, std::error_code>
    receive_dns_response(asio::ip::udp::socket& sock);

    fip::context& ctx;

};
