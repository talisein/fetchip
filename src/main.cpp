#include <iostream>
#include <cstring>
#include <netdb.h>
#include <array>
#include <format>
#include <random>
#include <optional>
#include <ranges>
#include <algorithm>
#include <expected>
#include <cxxopts.hpp>
#include <systemd/sd-journal.h>
#include <sys/socket.h>

#include <magic_enum/magic_enum.hpp>
#include "context.hpp"
#include "dns.hpp"
#include "dns_resolver.hpp"
#include "fetch_error.hpp"
#include "http_client.hpp"

using namespace std::literals;
enum class ServiceType {
    HTTP,
    HTTPS,
    DNS,
};

struct Service {
    std::string_view address;
    std::optional<std::string_view> path;
    std::optional<std::string_view> resolver;
    std::optional<DNSProviderAcceptedQueryType> query_type;
    ServiceType type;
};

/*
Candidates not yet in the list:
    http://ipecho.net/plain
    http://ident.me
    https://myip.dnsomatic.com
    https://checkip.amazonaws.com
    http://whatismyip.akamai.com
    https://myipv4.p1.opendns.com/get_my_ip
    https://ipinfo.io/ip
    https://api.ipify.org
    http://checkip.dyndns.org
    http://bot.whatismyipaddress.com
    TXT whoami.ds.akahelp.net (also whoami.ipv4. / whoami.ipv6.akahelp.net)
*/
constexpr auto services = std::to_array<Service>({
        {"http://ifconfig.me", "/ip", std::nullopt, std::nullopt, ServiceType::HTTP},
        {"https://ifconfig.me", "/ip", std::nullopt, std::nullopt, ServiceType::HTTPS},
        {"http://icanhazip.com", "/", std::nullopt, std::nullopt, ServiceType::HTTP},
        {"https://icanhazip.com", "/", std::nullopt, std::nullopt, ServiceType::HTTPS},
        {"myip.opendns.com", std::nullopt, "resolver1.opendns.com", DNSProviderAcceptedQueryType::A_OR_AAAA, ServiceType::DNS},
        {"whoami.akamai.net", std::nullopt, "ns1-1.akamaitech.net", DNSProviderAcceptedQueryType::A_ONLY, ServiceType::DNS},
        {"o-o.myaddr.l.google.com", std::nullopt, "ns1.google.com", DNSProviderAcceptedQueryType::TXT, ServiceType::DNS},
        {"whatismyip.on.quad9.net", std::nullopt, "dns.quad9.net", DNSProviderAcceptedQueryType::A_OR_AAAA, ServiceType::DNS},
});
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (s.type == ServiceType::HTTP || s.type == ServiceType::HTTPS) return s.path.has_value(); else return true; }) );
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (s.type == ServiceType::DNS) return s.resolver.has_value(); else return true; }) );
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (s.type == ServiceType::DNS) return s.query_type.has_value(); else return true; }) );

asio::awaitable<std::expected<std::string, std::error_code>>
query_http_public_ip(fip::context& ctx, const Service& service)
{
    auto res = co_await http_get(ctx, service.address, *service.path);
    if (!res) {
        ctx.log.debug("Failed to fetch ip from {}: {}", service.address, res.error().message());
        co_return std::unexpected(res.error());
    }
    auto body = std::string_view(*res);
    body = body.substr(0, body.find_last_not_of(" \t\r\n") + 1);
    auto family = address_family_of(body);
    if (!family) {
        ctx.log.debug("Response from {} is not an IP address: {}", service.address, body);
        co_return std::unexpected(std::make_error_code(std::errc::bad_message));
    }
    if (ctx.requested_family != fip::AddressFamily::Any && *family != ctx.requested_family) {
        ctx.log.debug("Response from {} is {}, wanted {}", service.address, magic_enum::enum_name(*family), magic_enum::enum_name(ctx.requested_family));
        co_return std::unexpected(std::make_error_code(std::errc::address_family_not_supported));
    }
    ctx.log.notice("Fetched current ip {} from {}", body, service.address);
    co_return std::string(body);
}

asio::awaitable<std::expected<std::string, std::error_code>>
query_public_ip(fip::context &ctx, const Service& service)
{
    if (service.type == ServiceType::HTTP || service.type == ServiceType::HTTPS) {
        co_return co_await query_http_public_ip(ctx, service);
    } else if (service.type == ServiceType::DNS) {
        DNSResolver resolver {ctx};
        co_return co_await resolver.query_dns_public_ip(service.address, *service.resolver, *service.query_type);
    } else {
        ctx.log.debug("Unknown service type {}", magic_enum::enum_integer(service.type));
        co_return std::unexpected(make_error_code(FetchError::UnknownServiceType));
    }
}

int main(int argc, char* argv[]) {
    cxxopts::Options options("fetchip", "Retrieve public IP from random service");
    options.add_options()
        ("h,help", "Show help")
        ("s,service", "Service type (HTTP or DNS)", cxxopts::value<std::string>())
        ("i,insecure", "Use HTTP instead of HTTPS", cxxopts::value<bool>()->default_value("false"))
        ("v,verbose", "Print verbose output to stderr")
        ("4", "Fetch the public IPv4 address")
        ("6", "Fetch the public IPv6 address")
        ;

    try {
        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            return 0;
        }

        std::optional<ServiceType> selectedType;

        if (result.count("service")) {
            selectedType = magic_enum::enum_cast<ServiceType>(result["service"].as<std::string>(), magic_enum::case_insensitive);
            if (!selectedType) {
                std::cerr << std::format("Unknown service type '{}'. Choose from ", result["service"].as<std::string>());
                std::ranges::for_each(magic_enum::enum_names<ServiceType>()
                                      | std::views::join_with(", "sv),
                                      [](const auto &sv) {
                                          std::cerr << sv;
                                      });
                std::cerr << "\n";
                return EXIT_FAILURE;
            }
        }

        if (result.count("4") && result.count("6")) {
            std::cerr << "-4 and -6 are mutually exclusive\n";
            return EXIT_FAILURE;
        }
        const auto family = result.count("4") ? fip::AddressFamily::V4
                          : result.count("6") ? fip::AddressFamily::V6
                          : fip::AddressFamily::Any;

        auto use_secure = !result["insecure"].as<bool>();
        auto secureServices = std::views::filter(services, [use_secure](const auto &service) {
            if (use_secure && service.type == ServiceType::HTTP)
                return false;
            if (!use_secure && service.type == ServiceType::HTTPS)
                return false;
            return true;
        });
        auto filteredServices = std::ranges::views::filter(secureServices, [selectedType](const auto& service) {
            if (selectedType) {
                return service.type == *selectedType;
            } else {
                return true;
            }
        }) | std::views::filter([family](const auto& service) {
            return !service.query_type || provider_supports(*service.query_type, family);
        });
        const size_t num_filteredServices = std::ranges::distance(filteredServices);
        if (num_filteredServices == 0) {
            std::cerr << "No service matches the selected options\n";
            return EXIT_FAILURE;
        }
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<size_t> dist(0, num_filteredServices - 1);
        const auto selectedService = *std::views::drop(filteredServices, dist(gen)).begin();

        fip::context ctx;
        ctx.requested_family = family;
        if (result.count("verbose")) {
            ctx.log.set_verbose(true);
        }

        std::expected<std::string, std::error_code> publicIp = std::unexpected(std::error_code {});
        asio::co_spawn(ctx.io_context, query_public_ip(ctx, selectedService),
                       [&publicIp](std::exception_ptr e, std::expected<std::string, std::error_code> result) {
                           if (e) std::rethrow_exception(e);
                           publicIp = std::move(result);
                       });
        ctx.io_context.run();
        if (publicIp) {
            std::cout << publicIp.value() << std::endl;
        } else {
            return EXIT_FAILURE;
        }

    } catch (const cxxopts::exceptions::exception& e) {
        std::cerr << "Error parsing options: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}
