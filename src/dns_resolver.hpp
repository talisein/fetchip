#pragma once

#include <system_error>
#include <expected>
#include <span>

#include "context.hpp"
#include "dns.hpp"

// What a whoami provider answers. It reports the address the query arrived from, so the transport family decides the answer family.
enum class DNSProviderAcceptedQueryType {
    A_OR_AAAA,
    A_ONLY,
    AAAA_ONLY,
    TXT,
};

// The family of a textual IP address, or nullopt if it is not one.
std::optional<fip::AddressFamily> address_family_of(std::string_view text);

bool provider_supports(DNSProviderAcceptedQueryType provider, fip::AddressFamily family);

// The wire query to send over a transport, or nullopt if the provider cannot answer over it.
std::optional<DNSQueryType> query_type_for(DNSProviderAcceptedQueryType provider, fip::AddressFamily transport);

class DNSResolver
{
public:
    DNSResolver(fip::context &ctx) : ctx(ctx) { };

    asio::awaitable<std::expected<std::string, std::error_code>>
    query_dns_public_ip(std::string_view host, std::string_view resolver, DNSProviderAcceptedQueryType provider);

    // The address in a whoami response received over transport.
    std::expected<std::string, std::error_code>
    parse_dns_response(std::span<const char> response, fip::AddressFamily transport);

private:
    asio::awaitable<std::expected<asio::ip::udp::resolver::results_type, std::error_code>>
    get_resolver_address(std::string_view resolver);

    std::expected<asio::ip::udp::socket, std::error_code>
    create_socket_and_connect(const asio::ip::udp::endpoint& ep);

    asio::awaitable<std::expected<void, std::error_code>>
    send_dns_query(asio::ip::udp::socket& sock, std::string_view host, DNSQueryType query_type);

    asio::awaitable<std::expected<std::string, std::error_code>>
    receive_dns_response(asio::ip::udp::socket& sock, fip::AddressFamily transport);

    fip::context& ctx;

};
