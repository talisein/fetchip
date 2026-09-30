#include <iostream>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <format>
#include <vector>
#include <optional>
#include <ranges>
#include <algorithm>
#include <expected>
#include <span>
#include <cxxopts.hpp>
#include <sys/socket.h>

#include <magic_enum/magic_enum.hpp>
#include "consensus_run.hpp"
#include "context.hpp"
#include "dns_resolver.hpp"
#include "fetch_error.hpp"
#include "http_client.hpp"
#include "name_resolver.hpp"
#include "services.hpp"

using namespace std::literals;

asio::awaitable<std::expected<std::string, std::error_code>>
query_http_public_ip(fip::context& ctx, Service service)
{
    auto res = co_await http_get(ctx, service.address, *service.path);
    if (!res) {
        ctx.log.debug("Failed to fetch ip from {}: {}", service.address, res.error().message());
        co_return std::unexpected(res.error());
    }
    const auto last = res->find_last_not_of(" \t\r\n"sv);
    res->erase(last == std::string::npos ? 0 : last + 1);
    auto family = address_family_of(*res);
    if (!family) {
        ctx.log.debug("Response from {} is not an IP address: {}", service.address, *res);
        co_return std::unexpected(std::make_error_code(std::errc::bad_message));
    }
    if (ctx.requested_family != fip::AddressFamily::Any && *family != ctx.requested_family) {
        ctx.log.debug("Response from {} is {}, wanted {}", service.address, magic_enum::enum_name(*family), magic_enum::enum_name(ctx.requested_family));
        co_return std::unexpected(std::make_error_code(std::errc::address_family_not_supported));
    }
    ctx.log.debug("Fetched current ip {} from {}", *res, service.address);
    co_return std::move(*res);
}

asio::awaitable<std::expected<std::string, std::error_code>>
query_public_ip(fip::context &ctx, Service service)
{
    if (service.type == ServiceType::HTTP || service.type == ServiceType::HTTPS) {
        co_return co_await query_http_public_ip(ctx, service);
    } else if (auto query = dns_query_type(service.type)) {
        DNSResolver resolver {ctx};
        co_return co_await resolver.query_dns_public_ip(service.address, *service.resolver, *query);
    } else {
        ctx.log.debug("Unknown service type {}", magic_enum::enum_integer(service.type));
        co_return std::unexpected(make_error_code(FetchError::UnknownServiceType));
    }
}

// Every host name is looked up through systemd-resolved, so no query can succeed without it.
boost::system::error_code connect_resolved(asio::io_context& io)
{
    asio::local::stream_protocol::socket socket {io};
    boost::system::error_code ec;
    socket.connect(asio::local::stream_protocol::endpoint {fip::resolved_address}, ec);
    return ec;
}

std::expected<void, std::error_code> print_line(std::string_view line)
{
    errno = 0;
    std::cout << line << '\n' << std::flush;
    if (std::cout) {
        return {};
    }
    // std::cout's buffer writes through fflush or write(2), which set errno when they fail.
    if (const auto err = errno; err != 0) {
        return std::unexpected(std::error_code(err, std::generic_category()));
    }
    return std::unexpected(std::make_error_code(std::io_errc::stream));
}

cxxopts::Options make_options()
{
    cxxopts::Options options("fetchip", "Retrieve public IP from random service");
    options.add_options()
        ("h,help", "Show help")
        ("s,service", "Service type (HTTP, HTTPS, DNS, DNS_A, DNS_AAAA or DNS_TXT); HTTP implies -i", cxxopts::value<std::string>())
        ("n,name", "Ask only the named service and print its answer, without consensus", cxxopts::value<std::string>())
        ("i,insecure", "Use HTTP instead of HTTPS", cxxopts::value<bool>()->default_value("false"))
        ("v,verbose", "Print verbose output to stderr")
        ("4", "Fetch the public IPv4 address")
        ("6", "Fetch the public IPv6 address")
        ;
    // Left out of --help; the bash completion reads its lists from here.
    options.add_options("completion")
        ("list", "Print the values -s (type) or -n (name) accepts", cxxopts::value<std::string>())
        ;
    return options;
}

int print_list(std::string_view list)
{
    std::vector<std::string_view> values;
    if (list == "type") {
        values = service_type_names();
    } else if (list == "name") {
        values = service_names();
    } else {
        std::cerr << std::format("Unknown list '{}'. Choose from type, name\n", list);
        return EXIT_FAILURE;
    }
    for (const auto value : values) {
        if (!print_line(value)) {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

std::string choices_message(std::string_view what, std::string_view given, std::span<const std::string_view> choices)
{
    auto message = std::format("Unknown {} '{}'. Choose from ", what, given);
    std::ranges::copy(choices | std::views::join_with(", "sv), std::back_inserter(message));
    return message;
}

std::expected<Selection, std::string> parse_selection(const cxxopts::ParseResult& result)
{
    Selection selection;

    if (result.count("service")) {
        const auto service = result["service"].as<std::string>();
        selection.dns = std::ranges::equal(service, "DNS"sv, {}, [](unsigned char c) { return std::toupper(c); });
        selection.type = magic_enum::enum_cast<ServiceType>(service, magic_enum::case_insensitive);
        if (!selection.dns && !selection.type) {
            return std::unexpected(choices_message("service type", service, service_type_names()));
        }
    }

    if (result.count("name")) {
        selection.name = result["name"].as<std::string>();
        if (!std::ranges::contains(services, *selection.name, &Service::name)) {
            return std::unexpected(choices_message("service", *selection.name, service_names()));
        }
    }

    if (result.count("4") && result.count("6")) {
        return std::unexpected("-4 and -6 are mutually exclusive"s);
    }
    selection.family = result.count("4") ? fip::AddressFamily::V4
                     : result.count("6") ? fip::AddressFamily::V6
                     : fip::AddressFamily::Any;

    selection.insecure = result["insecure"].as<bool>();
    return selection;
}

// One service cannot reach consensus, so its answer stands on its own.
// A name can have several entries (say, DNS_A and DNS_AAAA); try each
// in turn and return the first answer.
asio::awaitable<std::expected<std::string, std::error_code>>
first_answer(fip::context& ctx, std::span<const Service> candidates)
{
    for (const auto& service : candidates) {
        // A thrown query is one lost entry, as in the consensus path.
        std::expected<std::string, std::error_code> result;
        try {
            result = co_await query_public_ip(ctx, service);
        } catch (...) {
            log_exception(ctx, service.address, std::current_exception());
            continue;
        }
        if (!result) {
            ctx.log.error("{} failed: {}", service.address, result.error().message());
            continue;
        }
        // Canonical text, as the consensus path prints.
        boost::system::error_code ec;
        auto address = asio::ip::make_address(*result, ec);
        if (ec != boost::system::error_code {}) {
            ctx.log.error("{} did not answer with an address: {}", service.address, *result);
            continue;
        }
        co_return address.to_string();
    }
    co_return std::unexpected(make_error_code(FetchError::NoAnswer));
}

int print_answer(fip::context& ctx, const std::expected<std::string, std::error_code>& answer)
{
    if (!answer) {
        return EXIT_FAILURE;
    }
    if (const auto printed = print_line(*answer); !printed) {
        ctx.log.error("Cannot write {} to stdout: {}", *answer, printed.error().message());
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int main(int argc, char* argv[]) {
    auto options = make_options();

    try {
        auto result = options.parse(argc, argv);

        if (!result.unmatched().empty()) {
            std::cerr << std::format("Unexpected argument '{}'\n", result.unmatched().front());
            return EXIT_FAILURE;
        }

        if (result.count("help")) {
            if (!print_line(options.help({""}))) {
                return EXIT_FAILURE;
            }
            return EXIT_SUCCESS;
        }

        if (result.count("list")) {
            return print_list(result["list"].as<std::string>());
        }

        const auto selection = parse_selection(result);
        if (!selection) {
            std::cerr << selection.error() << "\n";
            return EXIT_FAILURE;
        }
        auto candidates = select_candidates(*selection);
        if (candidates.empty()) {
            std::cerr << "No service matches the selected options\n";
            return EXIT_FAILURE;
        }

        fip::context ctx;
        ctx.requested_family = selection->family;
        if (result.count("verbose")) {
            ctx.log.set_verbose(true);
        }

        if (const auto ec = connect_resolved(ctx.io_context); ec != boost::system::error_code {}) {
            std::cerr << std::format("systemd-resolved is required to use this program: cannot connect to {} ({})\n", fip::resolved_address, ec.message());
            return EXIT_FAILURE;
        }

        if (selection->name) {
            std::expected<std::string, std::error_code> answer = std::unexpected(make_error_code(FetchError::NoAnswer));
            asio::co_spawn(ctx.io_context, first_answer(ctx, candidates),
                           [&](std::exception_ptr e, std::expected<std::string, std::error_code> result) {
                               if (e) {
                                   log_exception(ctx, *selection->name, e);
                                   return;
                               }
                               answer = std::move(result);
                           });
            ctx.io_context.run();
            return print_answer(ctx, answer);
        }

        // Services are drawn from the back, so each is asked at most once.
        std::ranges::shuffle(candidates, ctx.rng);
        auto query = [&ctx](Service service) { return query_public_ip(ctx, service); };
        ConsensusRun consensus {ctx, std::move(candidates), query};
        return print_answer(ctx, consensus.run());

    } catch (const cxxopts::exceptions::exception& e) {
        std::cerr << "Error parsing options: " << e.what() << std::endl;
        return EXIT_FAILURE;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
