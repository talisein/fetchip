#include <ranges>
#include <span>
#include <spanstream>
#include <arpa/inet.h>
#include "dns_resolver.hpp"
#include "dns.hpp"
#include "name_resolver.hpp"

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

bool query_answers_family(DNSQueryType query, fip::AddressFamily family)
{
    switch (query) {
    case DNSQueryType::A:
        return family != fip::AddressFamily::V6;
    case DNSQueryType::AAAA:
        return family != fip::AddressFamily::V4;
    case DNSQueryType::TXT:
        return true;
    default:
        return false;
    }
}

namespace {
    constexpr asio::ip::port_type dns_port = 53;
}

std::expected<asio::ip::udp::socket, std::error_code>
DNSResolver::create_socket_and_connect(const asio::ip::udp::endpoint& ep)
{
    using asio::ip::udp;

    boost::system::error_code ec;
    ctx.log.debug("Connecting to {} port {}", ep.address().to_string(), ep.port());
    if (!ep.address().is_v4() && !ep.address().is_v6()) {
        ctx.log.debug("Trying to connect to socket to unexpected family {}", ep.address().to_string());
        return std::unexpected(std::make_error_code(std::errc::address_family_not_supported));
    }

    // Open with an error_code: a host without IPv6 refuses the v6 socket
    // outright, and that must fail this one query, not throw.
    udp::socket s(ctx.io_context);
    s.open(ep.address().is_v4() ? udp::v4() : udp::v6(), ec);
    if (ec != boost::system::error_code {}) {
        ctx.log.debug("udp socket open failure: {}", ec.message());
        return std::unexpected(ec);
    }
    s.connect(ep, ec);
    if (ec != boost::system::error_code {}) {
        ctx.log.debug("udp connection failure: {}", ec.message());
        return std::unexpected(ec);
    }
    ctx.log.debug("Connected to {}", ep.address().to_string());
    return s;
}

asio::awaitable<std::expected<DNSMessage, std::error_code>>
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

    if (ec != boost::system::error_code {}) {
        ctx.log.debug("Failed to send DNS query: {}", ec.message());
        co_return std::unexpected(ec);
    }

    ctx.log.debug("Sent DNS query: {}", message);
    co_return message;
}

namespace {
    template<class... Ts>
    struct overloads : Ts... { using Ts::operator()...; };

    bool same_name(std::string_view a, std::string_view b)
    {
        return std::ranges::equal(a, b, [](unsigned char x, unsigned char y) {
            return std::tolower(x) == std::tolower(y);
        });
    }

    bool same_question(const DNSQuestion& a, const DNSQuestion& b)
    {
        return a.blob.qtype == b.blob.qtype && a.blob.qclass == b.blob.qclass && same_name(a.qname, b.qname);
    }
}

asio::awaitable<std::expected<std::string, std::error_code>>
DNSResolver::receive_dns_response(asio::ip::udp::socket& sock, const DNSMessage& query, fip::AddressFamily transport) {
    const auto deadline = std::chrono::steady_clock::now() + fip::dns_resolution_timeout;
    std::array<char, DNSBufferSize> buf;
    std::expected<std::string, std::error_code> result;

    while (true) {
        const auto remaining = std::max(deadline - std::chrono::steady_clock::now(), std::chrono::steady_clock::duration::zero());
        auto [ec, bytes_received] = co_await sock.async_receive(asio::buffer(buf),
            asio::cancel_after(remaining, asio::as_tuple(asio::use_awaitable)));

        if (ec != boost::system::error_code {} || 0 == bytes_received) {
            std::error_code failure = ec;
            // operation_aborted is the timeout only if the caller did not cancel the query.
            const auto cancelled = (co_await asio::this_coro::cancellation_state).cancelled();
            if (ec == asio::error::operation_aborted && cancelled == asio::cancellation_type::none) {
                ctx.log.debug("No response from {} within {}", sock.remote_endpoint(ec).address().to_string(), fip::dns_resolution_timeout);
                failure = std::make_error_code(std::errc::timed_out);
            } else if (ec != boost::system::error_code {}) {
                ctx.log.debug("Failed to receive UDP response: {}. Got {} bytes.", ec.message(), bytes_received);
            } else {
                ctx.log.debug("Got an empty UDP response");
                failure = make_error_code(DNSError::DNSResolverEmptyResponse);
            }
            result = std::unexpected(failure);
            break;
        }

        result = parse_dns_response(std::span(buf).first(bytes_received), query, transport);
        if (result || result.error() != make_error_code(DNSError::DNSResolverMismatchedResponse)) {
            break;
        }
        ctx.log.debug("Discarding a response that does not answer our query");
    }

    boost::system::error_code close_ec;
    sock.close(close_ec);
    if (close_ec != boost::system::error_code {}) {
        ctx.log.warning("Failed to close UDP socket: {}. Ignoring...", close_ec.message());
    }

    co_return result;
}

std::expected<std::string, std::error_code>
DNSResolver::parse_dns_response(std::span<const char> response, const DNSMessage& query, fip::AddressFamily transport) {
    std::ispanstream ss(response);

    auto message = DNSMessage::deserialize(ctx, ss);
    if (!message) {
        ctx.log.debug("Failed to deserialize DNSMessage: {}", message.error().message());
        return std::unexpected(message.error());
    }
    ctx.log.debug("{}", *message);

    if (message->get_header().id != query.get_header().id) {
        ctx.log.debug("Response ID {:#x} does not match query ID {:#x}", message->get_header().id, query.get_header().id);
        return std::unexpected(make_error_code(DNSError::DNSResolverMismatchedResponse));
    }
    if (!(message->get_header().flags & QueryResponse)) {
        ctx.log.debug("Message is not a response");
        return std::unexpected(make_error_code(DNSError::DNSResolverMismatchedResponse));
    }
    if (!std::ranges::equal(message->get_questions(), query.get_questions(), same_question)) {
        ctx.log.debug("Response question does not match the query");
        return std::unexpected(make_error_code(DNSError::DNSResolverMismatchedResponse));
    }

    if (message->get_header().get_response_code() != DNSResponseCodes::NO_ERROR) {
        ctx.log.debug("Bailing due to error response code");
        return std::unexpected(make_error_code(DNSError::DNSResolverErrorResponse));
    }

    auto answers = message->get_answers();
    if (answers.size() == 0) {
        ctx.log.debug("Bailing due to zero answers");
        return std::unexpected(make_error_code(DNSError::DNSResolverNoAnswers));
    }
    // Other record types, such as a CNAME ahead of the answer, carry no address and their rdata is left unparsed.
    auto answer = std::ranges::find_if(answers, [](const auto& rr) {
        return rr.blob.type == DNSQueryType::A || rr.blob.type == DNSQueryType::AAAA || rr.blob.type == DNSQueryType::TXT;
    });
    if (answer == answers.end()) {
        ctx.log.debug("Bailing because no answer is an A, AAAA or TXT record");
        return std::unexpected(make_error_code(DNSError::DNSResolverUnexpectedAnswer));
    }

    using answer_t = std::expected<std::string, std::error_code>;
    auto address = std::visit(overloads
               {
                   [&](const RData_A& a) -> answer_t {
                       if (transport != fip::AddressFamily::V4) {
                           ctx.log.debug("Got an A answer over {}", magic_enum::enum_name(transport));
                           return std::unexpected(make_error_code(DNSError::DNSResolverWrongFamily));
                       }
                       return asio::ip::address_v4(a.ipv4_address.s_addr).to_string();
                   },
                   [&](const RData_AAAA& aaaa) -> answer_t {
                       if (transport != fip::AddressFamily::V6) {
                           ctx.log.debug("Got an AAAA answer over {}", magic_enum::enum_name(transport));
                           return std::unexpected(make_error_code(DNSError::DNSResolverWrongFamily));
                       }
                       return asio::ip::address_v6(std::to_array(aaaa.ipv6_address.s6_addr)).to_string();
                   },
                   [&](const RData_TXT& txt) -> answer_t {
                       // Some providers tag the address, as in akahelp's "ns" "<ip>".
                       const auto text = std::ranges::find_if(txt.strings, [](const auto& s) { return address_family_of(s).has_value(); });
                       if (text == txt.strings.end()) {
                           ctx.log.debug("TXT answer holds no IP address: {}", txt.strings);
                           return std::unexpected(make_error_code(DNSError::DNSResolverUnexpectedAnswer));
                       }
                       const auto family = *address_family_of(*text);
                       ctx.log.debug("TXT answer {} is {}", *text, magic_enum::enum_name(family));
                       if (family != transport) {
                           ctx.log.debug("TXT answer family does not match transport {}", magic_enum::enum_name(transport));
                           return std::unexpected(make_error_code(DNSError::DNSResolverWrongFamily));
                       }
                       return *text;
                   },
                   [&](const auto& unknown) -> answer_t {
                       ctx.log.debug("Unknown RData in variant?! {}", typeid(unknown).name());
                       return std::unexpected(make_error_code(DNSError::DNSResolverUnexpectedAnswer));
                   }
               }, answer->rdata);
    if (address) {
        ctx.log.debug("Got response IP: {}", *address);
    }
    return address;
}

asio::awaitable<std::expected<std::string, std::error_code>>
DNSResolver::query_dns_public_ip(std::string_view host, std::string_view resolver, DNSQueryType query) {
    auto resolver_addrs = co_await resolve_host(ctx, resolver);
    if (!resolver_addrs) {
        ctx.log.debug("Failed to resolve the resolver: {}", resolver_addrs.error().message());
        co_return std::unexpected(resolver_addrs.error());
    }

    std::error_code last_error {};

    for (const auto& address : *resolver_addrs) {
        const auto transport = fip::family_of(address);
        if (!query_answers_family(query, transport)) {
            last_error = make_error_code(DNSError::DNSResolverWrongFamily);
            ctx.log.debug("Skipping {}: {} cannot answer over {}", address.to_string(), magic_enum::enum_name(query), magic_enum::enum_name(transport));
            continue;
        }

        const asio::ip::udp::endpoint resolver_addr {address, dns_port};
        auto sock = create_socket_and_connect(resolver_addr);
        if (!sock) {
            last_error = sock.error();
            ctx.log.debug("Looping: {}", last_error.message());
            continue;
        }

        auto sent_query = co_await send_dns_query(*sock, host, query);
        if (!sent_query) {
            last_error = sent_query.error();
            ctx.log.debug("Looping: {}", last_error.message());
            continue;
        }

        auto result = co_await receive_dns_response(*sock, *sent_query, transport);
        if (result.has_value()) {
            ctx.log.debug("Fetched current ip {} from {}", *result, host);
            co_return result;
        } else {
            last_error = result.error();
            ctx.log.debug("Looping: {}", last_error.message());
            continue;
        }
    }

    co_return std::unexpected(last_error);
}
