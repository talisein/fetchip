#pragma once

#include <system_error>
#include <expected>
#include <span>

#include "context.hpp"
#include "dns.hpp"

// The family of a textual IP address, or nullopt if it is not one.
std::optional<fip::AddressFamily> address_family_of(std::string_view text);

// A whoami provider reports the address the query arrived from, so an A query must travel over IPv4 and an AAAA over IPv6.
bool query_answers_family(DNSQueryType query, fip::AddressFamily family);

class DNSResolver
{
public:
    DNSResolver(fip::context &ctx) : ctx(ctx) { };

    asio::awaitable<std::expected<std::string, std::error_code>>
    query_dns_public_ip(std::string_view host, std::string_view resolver, DNSQueryType query);

    std::expected<std::string, std::error_code>
    parse_dns_response(std::span<const char> response, const DNSMessage& query, fip::AddressFamily transport);

private:
    asio::awaitable<std::expected<asio::ip::udp::resolver::results_type, std::error_code>>
    get_resolver_address(std::string_view resolver);

    std::expected<asio::ip::udp::socket, std::error_code>
    create_socket_and_connect(const asio::ip::udp::endpoint& ep);

    asio::awaitable<std::expected<DNSMessage, std::error_code>>
    send_dns_query(asio::ip::udp::socket& sock, std::string_view host, DNSQueryType query_type);

    asio::awaitable<std::expected<std::string, std::error_code>>
    receive_dns_response(asio::ip::udp::socket& sock, const DNSMessage& query, fip::AddressFamily transport);

    fip::context& ctx;

};
