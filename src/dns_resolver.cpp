#include <ranges>
#include <span>
#include <spanstream>
#include "dns_resolver.hpp"
#include "dns.hpp"

std::expected<asio::ip::udp::socket, asio::error_code>
DNSResolver::create_socket_and_connect(const asio::ip::udp::endpoint& ep)
{
    using asio::ip::udp;

    asio::error_code ec;
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
    return std::unexpected(asio::error::basic_errors::address_family_not_supported);
}

std::expected<void, std::error_code>
DNSResolver::send_dns_query(asio::ip::udp::socket& sock, std::string_view host)
{
    DNSMessage message(ctx);
    // TODO: variable query type depending on service and request
    message.add_question(host, DNSQueryType::A);

    std::array<char, DNSBufferSize> buf;
    std::ospanstream ss {buf};
    auto serialized = message.serialize(ss);
    if (!serialized) {
        ctx.log.debug("Failed to serialize: {}", serialized.error().message());
        return std::unexpected(serialized.error());
    }

    // TODO: safe signed->unsigned cast
    asio::const_buffer b{buf.data(), static_cast<size_t>(ss.tellp())};
//    auto range = std::views::take(buf, ss.tellp());
    asio::socket_base::message_flags flags { };
    asio::error_code ec;

    sock.send(b, flags, ec);

    if (ec) {
        ctx.log.debug("Failed to send DNS query: {}", ec.message());
        return std::unexpected(ec);
    }

    ctx.log.debug("Sent DNS query: {}", message);
    return {};
}

namespace {
    template<class... Ts>
    struct overloads : Ts... { using Ts::operator()...; };
}

// Function to receive the DNS response and extract the IPv4 address
std::expected<std::string, std::error_code>
DNSResolver::receive_dns_response(asio::ip::udp::socket& sock) {
    asio::error_code ec;
    asio::socket_base::message_flags flags { };
    std::array<char, DNSBufferSize> buf;
    auto bytes_received = sock.receive(asio::buffer(buf), flags, ec);

    if (ec || 0 == bytes_received) {
        ctx.log.debug("Failed to receive UDP response: {}. Got {} bytes.", ec.message(), bytes_received);
        asio::error_code close_ec;
        sock.close(close_ec);
        if (close_ec) {
            ctx.log.debug("Couldn't even close the socket?! {}", close_ec.message());
        }
        return std::unexpected(ec);
    }
    sock.close(ec);
    if (ec) {
        ctx.log.warning("Failed to close UDP socket: {}. Ignoring...", ec.message());
    }

    auto view = std::views::take(buf, bytes_received);
    std::ispanstream ss(view);

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

    std::array<char, INET6_ADDRSTRLEN + 1> address {};
    const char *res = nullptr;
    std::visit(overloads
               {
                   [&](const RData_A& a) {
                       res = inet_ntop(AF_INET, &a.ipv4_address, address.data(), address.size());
                   },
                   [&](const RData_AAAA&) {
                       res = inet_ntop(AF_INET6, std::addressof(std::get<RData_AAAA>(answers[0].rdata).ipv6_address), address.data(), address.size());
                   },
                   [&](const RData_TXT& txt) {
                       std::ranges::copy(txt.text, address.data());
                       res = address.data();
                   },
                   [&](const auto& unknown) {
                       ctx.log.debug("Unknown RData in variant?! {}", typeid(unknown).name());
                   }
               }, answers[0].rdata);
    if (nullptr == res) {
        ctx.log.debug("Bailing because we couldn't populate the result string");
        return std::unexpected(make_error_code(DNSError::DNSResolverErrorResponse));
    }

    ctx.log.debug("Got response IP: {}", res);
    return std::string(res);
}

std::expected<asio::ip::basic_resolver<asio::ip::udp>::results_type, asio::error_code>
DNSResolver::get_resolver_address(std::string_view resolver_name)
{
    using namespace std::literals;
    asio::ip::basic_resolver<asio::ip::udp> resolver {ctx.io_context};
    asio::error_code ec;
    auto result = resolver.resolve(resolver_name, "domain"sv, ec);
    if (ec) {
        ctx.log.debug("Failed to resolve the resolver: {}", ec.message());
        return std::unexpected(ec);
    }

    return result;
}

std::expected<std::string, std::error_code>
DNSResolver::query_dns_public_ip(std::string_view host, std::string_view resolver) {
    auto resolver_addrs = get_resolver_address(resolver);
    if (!resolver_addrs) {
        return std::unexpected(resolver_addrs.error());
    }

    std::error_code last_error {};

    for (const auto& resolver_addr : *resolver_addrs) {
        auto sock = create_socket_and_connect(resolver_addr);
        if (!sock) {
            last_error = sock.error();
            ctx.log.debug("Looping: {}", last_error.message());
            continue;
        }

        auto sent_query = send_dns_query(*sock, host);
        if (!sent_query) {
            last_error = sent_query.error();
            ctx.log.debug("Looping: {}", last_error.message());
            continue;
        }

        auto result = receive_dns_response(*sock);
        if (result.has_value()) {
            ctx.log.notice("Fetched current ip {} from {}", *result, host);
            return result;
        } else {
            last_error = result.error();
            ctx.log.debug("Looping: {}", last_error.message());
            continue;
        }
    }

    return std::unexpected(last_error);
}
