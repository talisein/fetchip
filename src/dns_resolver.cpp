#include <bit>
#include <ranges>
#include <span>
#include <spanstream>
#include <arpa/inet.h>
#include "dns_resolver.hpp"
#include "dns.hpp"

std::optional<fip::AddressFamily> address_family_of(std::string_view text)
{
    std::array<char, INET6_ADDRSTRLEN> buf {};
    if (text.size() >= buf.size()) {
        return std::nullopt;
    }
    std::ranges::copy(text, buf.data());

    in6_addr scratch;
    if (inet_pton(AF_INET, buf.data(), &scratch) == 1) {
        return fip::AddressFamily::V4;
    }
    if (inet_pton(AF_INET6, buf.data(), &scratch) == 1) {
        return fip::AddressFamily::V6;
    }
    return std::nullopt;
}

bool provider_supports(DNSProviderAcceptedQueryType provider, fip::AddressFamily family)
{
    switch (provider) {
    case DNSProviderAcceptedQueryType::A_ONLY:
        return family != fip::AddressFamily::V6;
    case DNSProviderAcceptedQueryType::AAAA_ONLY:
        return family != fip::AddressFamily::V4;
    case DNSProviderAcceptedQueryType::A_OR_AAAA:
    case DNSProviderAcceptedQueryType::TXT:
        return true;
    }
    return false;
}

std::optional<DNSQueryType> query_type_for(DNSProviderAcceptedQueryType provider, fip::AddressFamily transport)
{
    if (transport == fip::AddressFamily::Any || !provider_supports(provider, transport)) {
        return std::nullopt;
    }
    if (provider == DNSProviderAcceptedQueryType::TXT) {
        return DNSQueryType::TXT;
    }
    return transport == fip::AddressFamily::V4 ? DNSQueryType::A : DNSQueryType::AAAA;
}

namespace {
    fip::AddressFamily family_of(const asio::ip::udp::endpoint& ep)
    {
        return ep.address().is_v6() ? fip::AddressFamily::V6 : fip::AddressFamily::V4;
    }
}

std::expected<asio::ip::udp::socket, std::error_code>
DNSResolver::create_socket_and_connect(const asio::ip::udp::endpoint& ep)
{
    using asio::ip::udp;

    boost::system::error_code ec;
    ctx.log.debug("Connecting to {} port {}", ep.address().to_string(), ep.port());
    if (ep.address().is_v4()) {
        udp::socket s(ctx.io_context, udp::endpoint(udp::v4(), 0));
        s.connect(ep, ec);
        if (ec) {
            ctx.log.debug("udp connection failure: {}", ec.message());
            return std::unexpected(ec);
        }
        ctx.log.debug("Connected to {}", ep.address().to_string());
        return s;
    } else if (ep.address().is_v6()) {
        udp::socket s(ctx.io_context, udp::endpoint(udp::v6(), 0));
        s.connect(ep, ec);
        if (ec) {
            ctx.log.debug("udp connection failure: {}", ec.message());
            return std::unexpected(ec);
        }
        return s;
    }

    ctx.log.debug("Trying to connect to socket to unexpected family {}", ep.address().to_string());
    return std::unexpected(std::make_error_code(std::errc::address_family_not_supported));
}

asio::awaitable<std::expected<void, std::error_code>>
DNSResolver::send_dns_query(asio::ip::udp::socket& sock, std::string_view host, DNSQueryType query_type)
{
    DNSMessage message(ctx);
    message.add_question(host, query_type);

    std::array<char, DNSBufferSize> buf;
    std::ospanstream ss {buf};
    auto serialized = message.serialize(ss);
    if (!serialized) {
        ctx.log.debug("Failed to serialize: {}", serialized.error().message());
        co_return std::unexpected(serialized.error());
    }

    // TODO: safe signed->unsigned cast
    asio::const_buffer b{buf.data(), static_cast<size_t>(ss.tellp())};
    auto [ec, bytes_sent] = co_await sock.async_send(b, asio::as_tuple(asio::use_awaitable));

    if (ec) {
        ctx.log.debug("Failed to send DNS query: {}", ec.message());
        co_return std::unexpected(ec);
    }

    ctx.log.debug("Sent DNS query: {}", message);
    co_return std::expected<void, std::error_code> {};
}

namespace {
    template<class... Ts>
    struct overloads : Ts... { using Ts::operator()...; };
}

asio::awaitable<std::expected<std::string, std::error_code>>
DNSResolver::receive_dns_response(asio::ip::udp::socket& sock, fip::AddressFamily transport) {
    std::array<char, DNSBufferSize> buf;
    auto [ec, bytes_received] = co_await sock.async_receive(asio::buffer(buf),
        asio::cancel_after(fip::dns_resolution_timeout, asio::as_tuple(asio::use_awaitable)));

    if (ec || 0 == bytes_received) {
        std::error_code result = ec;
        if (ec == asio::error::operation_aborted) {
            ctx.log.debug("No response from {} within {}", sock.remote_endpoint(ec).address().to_string(), fip::dns_resolution_timeout);
            result = std::make_error_code(std::errc::timed_out);
        } else {
            ctx.log.debug("Failed to receive UDP response: {}. Got {} bytes.", ec.message(), bytes_received);
        }
        boost::system::error_code close_ec;
        sock.close(close_ec);
        if (close_ec) {
            ctx.log.debug("Couldn't even close the socket?! {}", close_ec.message());
        }
        co_return std::unexpected(result);
    }
    sock.close(ec);
    if (ec) {
        ctx.log.warning("Failed to close UDP socket: {}. Ignoring...", ec.message());
    }

    co_return parse_dns_response(std::span(buf).first(bytes_received), transport);
}

std::expected<std::string, std::error_code>
DNSResolver::parse_dns_response(std::span<const char> response, fip::AddressFamily transport) {
    std::ispanstream ss(response);

    auto message = DNSMessage::deserialize(ctx, ss);
    if (!message) {
        ctx.log.debug("Failed to deserialize DNSMessage: {}", message.error().message());
        return std::unexpected(message.error());
    }
    ctx.log.debug("{}", *message);

    if (message->get_header().get_response_code() != DNSResponseCodes::NO_ERROR) {
        ctx.log.debug("Bailing due to error response code");
        return std::unexpected(make_error_code(DNSError::DNSResolverErrorResponse));
    }

    auto answers = message->get_answers();
    if (answers.size() == 0) {
        ctx.log.debug("Bailing due to zero answers");
        return std::unexpected(make_error_code(DNSError::DNSResolverNoAnswers));
    }

    // TODO: refactor to propagate error types and not use char*
    std::array<char, INET6_ADDRSTRLEN + 1> address {};
    const char *res = nullptr;
    DNSError failure = DNSError::DNSResolverErrorResponse;
    std::visit(overloads
               {
                   [&](const RData_A& a) {
                       if (transport != fip::AddressFamily::V4) {
                           ctx.log.debug("Got an A answer over {}", magic_enum::enum_name(transport));
                           failure = DNSError::DNSResolverWrongFamily;
                           return;
                       }
                       const in_addr network_order { std::endian::native == std::endian::big ? a.ipv4_address.s_addr : std::byteswap(a.ipv4_address.s_addr) };
                       res = inet_ntop(AF_INET, &network_order, address.data(), address.size());
                   },
                   [&](const RData_AAAA& aaaa) {
                       if (transport != fip::AddressFamily::V6) {
                           ctx.log.debug("Got an AAAA answer over {}", magic_enum::enum_name(transport));
                           failure = DNSError::DNSResolverWrongFamily;
                           return;
                       }
                       res = inet_ntop(AF_INET6, &aaaa.ipv6_address, address.data(), address.size());
                   },
                   [&](const RData_TXT& txt) {
                       auto family = address_family_of(txt.text);
                       if (!family) {
                           ctx.log.debug("TXT answer is not an IP address: {}", txt.text);
                           failure = DNSError::DNSResolverUnexpectedAnswer;
                           return;
                       }
                       ctx.log.debug("TXT answer {} is {}", txt.text, magic_enum::enum_name(*family));
                       if (*family != transport) {
                           ctx.log.debug("TXT answer family does not match transport {}", magic_enum::enum_name(transport));
                           failure = DNSError::DNSResolverWrongFamily;
                           return;
                       }
                       std::ranges::copy(txt.text, address.data());
                       res = address.data();
                   },
                   [&](const auto& unknown) {
                       ctx.log.debug("Unknown RData in variant?! {}", typeid(unknown).name());
                   }
               }, answers[0].rdata);
    if (nullptr == res) {
        ctx.log.debug("Bailing because we couldn't populate the result string");
        return std::unexpected(make_error_code(failure));
    }

    ctx.log.debug("Got response IP: {}", res);
    return std::string(res);
}

asio::awaitable<std::expected<asio::ip::udp::resolver::results_type, std::error_code>>
DNSResolver::get_resolver_address(std::string_view resolver_name)
{
    using namespace std::literals;
    constexpr auto token = asio::as_tuple(asio::use_awaitable);
    asio::ip::udp::resolver resolver {ctx.io_context};
    boost::system::error_code ec;
    asio::ip::udp::resolver::results_type result;
    switch (ctx.requested_family) {
    case fip::AddressFamily::V4:
        std::tie(ec, result) = co_await resolver.async_resolve(asio::ip::udp::v4(), resolver_name, "domain"sv, token);
        break;
    case fip::AddressFamily::V6:
        std::tie(ec, result) = co_await resolver.async_resolve(asio::ip::udp::v6(), resolver_name, "domain"sv, token);
        break;
    case fip::AddressFamily::Any:
        std::tie(ec, result) = co_await resolver.async_resolve(resolver_name, "domain"sv, token);
        break;
    }
    if (ec) {
        ctx.log.debug("Failed to resolve the resolver: {}", ec.message());
        co_return std::unexpected(ec);
    }

    co_return result;
}

asio::awaitable<std::expected<std::string, std::error_code>>
DNSResolver::query_dns_public_ip(std::string_view host, std::string_view resolver, DNSProviderAcceptedQueryType provider) {
    auto resolver_addrs = co_await get_resolver_address(resolver);
    if (!resolver_addrs) {
        co_return std::unexpected(resolver_addrs.error());
    }

    std::error_code last_error {};

    for (const auto& resolver_addr : *resolver_addrs) {
        const auto transport = family_of(resolver_addr.endpoint());
        const auto query_type = query_type_for(provider, transport);
        if (!query_type) {
            last_error = make_error_code(DNSError::DNSResolverWrongFamily);
            ctx.log.debug("Skipping {}: {} cannot answer over {}", resolver_addr.endpoint().address().to_string(), magic_enum::enum_name(provider), magic_enum::enum_name(transport));
            continue;
        }

        auto sock = create_socket_and_connect(resolver_addr);
        if (!sock) {
            last_error = sock.error();
            ctx.log.debug("Looping: {}", last_error.message());
            continue;
        }

        auto sent_query = co_await send_dns_query(*sock, host, *query_type);
        if (!sent_query) {
            last_error = sent_query.error();
            ctx.log.debug("Looping: {}", last_error.message());
            continue;
        }

        auto result = co_await receive_dns_response(*sock, transport);
        if (result.has_value()) {
            ctx.log.notice("Fetched current ip {} from {}", *result, host);
            co_return result;
        } else {
            last_error = result.error();
            ctx.log.debug("Looping: {}", last_error.message());
            continue;
        }
    }

    co_return std::unexpected(last_error);
}
