#include <iostream>
#include <cstring>
#include <netdb.h>
#include <httplib.h>
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

#include <magic_enum.hpp>
#include "context.hpp"
#include "dns_resolver.hpp"

using namespace std::literals;
enum class ServiceType {
    HTTP,
    HTTPS,
    DNS,
    // Add more service types if needed
};

struct Service {
    std::string_view address;
    std::optional<std::string_view> path;
    std::optional<std::string_view> resolver;
    ServiceType type;
};

/*
http://ipecho.net/plain
http://ident.me
https://myip.dnsomatic.com
https://checkip.amazonaws.com
http://whatismyip.akamai.com
https://myipv4.p1.opendns.com/get_my_ip
dig +short ANY whoami.akamai.net @ns1-1.akamaitech.net
dig +short ANY o-o.myaddr.l.google.com @ns1.google.com
*/


// Initialize the array using std::to_array
constexpr auto services = std::to_array<Service>({
        {"http://ifconfig.me", "/ip", std::nullopt, ServiceType::HTTP},
        {"https://ifconfig.me", "/ip", std::nullopt, ServiceType::HTTPS},
        {"http://icanhazip.com", "/", std::nullopt, ServiceType::HTTP},
        {"https://icanhazip.com", "/", std::nullopt, ServiceType::HTTPS},
        {"myip.opendns.com", std::nullopt, "resolver1.opendns.com", ServiceType::DNS},
        //{"whoami.akamai.net", std::nullopt, "ns1-1.akamaitech.net", ServiceType::DNS},
        //{"o-o.myaddr.l.google.com", std::nullopt, "ns1.google.com", ServiceType::DNS},// TXT
        // Add more services if needed
});
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (s.type == ServiceType::HTTP || s.type == ServiceType::HTTPS) return s.path.has_value(); else return true; }) );
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (s.type == ServiceType::DNS) return s.resolver.has_value(); else return true; }) );

std::expected<std::string, std::error_code>
query_http_public_ip(fip::context& ctx, const Service& service)
{
    httplib::Client client(std::string(service.address));
    auto res = client.Get(std::string(*service.path));
    if (res && res->status == 200) {
        ctx.log.notice("Fetched current ip {} from {}", res->body, service.address);
        return res->body;
    } else {
        ctx.log.debug("Failed to fetch ip from {}: {} ({})", service.address, httplib::to_string(res.error()), res->status);
        return std::unexpected(std::make_error_code(std::errc::io_error));
    }
}

std::expected<std::string, std::error_code>
query_public_ip(fip::context &ctx, const Service& service)
{
    if (service.type == ServiceType::HTTP || service.type == ServiceType::HTTPS) {
        auto res = query_http_public_ip(ctx, service);
        if (!res) return std::unexpected(res.error());
        else return res.value();
    } else if (service.type == ServiceType::DNS) {
        DNSResolver resolver {ctx};
        auto res = resolver.query_dns_public_ip(service.address, *service.resolver);
        if (!res) return std::unexpected(res.error());
        else return res.value();
    } else {
        return "Unknown service type.";
    }
}

int main(int argc, char* argv[]) {
    // Command line option parsing with cxxopts
    cxxopts::Options options("fetchip", "Retrieve public IP from random service");
    options.add_options()
        ("h,help", "Show help")
        ("s,service", "Service type (HTTP or DNS)", cxxopts::value<std::string>())
        ("i,insecure", "Use HTTP instead of HTTPS", cxxopts::value<bool>()->default_value("false"))
        ("v,verbose", "Print verbose output to stderr")
        ;

    try {
        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            return 0;
        }

        // Transform the service option into a ServiceType enum
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
        if (selectedType) {
            std::cerr << "Selected service type " << magic_enum::enum_name(*selectedType) << "\n";
        } else {
            std::cerr << "No selected service type\n";
        }

        auto use_secure = !result["insecure"].as<bool>();
        auto secureServices = std::views::filter(services, [use_secure](const auto &service) {
            if (use_secure && service.type == ServiceType::HTTP)
                return false;
            if (!use_secure && service.type == ServiceType::HTTPS)
                return false;
            return true;
        });
        // Filter services based on the selected type
        auto filteredServices = std::ranges::views::filter(secureServices, [selectedType](const auto& service) {
            if (selectedType) {
                return service.type == *selectedType;
            } else {
                return true;
            }
        });
        const size_t num_filteredServices = std::ranges::distance(filteredServices);

        std::cerr << "num services = " << num_filteredServices << '\n';
        // Randomly select a service from the filtered range
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<size_t> dist(0, num_filteredServices - 1);
        auto rng = dist(gen);
        std::cerr << "Got random " << rng << '\n';
        const auto selectedService = *std::views::drop(filteredServices, rng).begin();


        // Print verbose output to stderr
        fip::context ctx;
        if (result.count("verbose")) {
            ctx.log.set_verbose(true);
        }

        // Query the selected service for public IP
        const auto publicIp = query_public_ip(ctx, selectedService);

        // Print the result
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
