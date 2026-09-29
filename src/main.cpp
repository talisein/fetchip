#include <iostream>
#include <cstring>
#include <netdb.h>
#include <array>
#include <format>
#include <list>
#include <vector>
#include <optional>
#include <ranges>
#include <algorithm>
#include <expected>
#include <cxxopts.hpp>
#include <systemd/sd-journal.h>
#include <sys/socket.h>

#include <magic_enum/magic_enum.hpp>
#include "consensus.hpp"
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
    // Shared by the HTTP and HTTPS entries for one provider; -i picks between them.
    std::string_view name;
    std::string_view address;
    std::optional<std::string_view> path;
    std::optional<std::string_view> resolver;
    std::optional<DNSProviderAcceptedQueryType> query_type;
    ServiceType type;
};

constexpr auto services = std::to_array<Service>({
        {"ifconfig.me", "http://ifconfig.me", "/ip", std::nullopt, std::nullopt, ServiceType::HTTP},
        {"ifconfig.me", "https://ifconfig.me", "/ip", std::nullopt, std::nullopt, ServiceType::HTTPS},
        {"icanhazip", "http://icanhazip.com", "/", std::nullopt, std::nullopt, ServiceType::HTTP},
        {"icanhazip", "https://icanhazip.com", "/", std::nullopt, std::nullopt, ServiceType::HTTPS},
        {"ipecho", "http://ipecho.net", "/plain", std::nullopt, std::nullopt, ServiceType::HTTP},
        {"ipecho", "https://ipecho.net", "/plain", std::nullopt, std::nullopt, ServiceType::HTTPS},
        {"ident.me", "http://ident.me", "/", std::nullopt, std::nullopt, ServiceType::HTTP},
        {"ident.me", "https://ident.me", "/", std::nullopt, std::nullopt, ServiceType::HTTPS},
        {"dnsomatic", "http://myip.dnsomatic.com", "/", std::nullopt, std::nullopt, ServiceType::HTTP},
        {"dnsomatic", "https://myip.dnsomatic.com", "/", std::nullopt, std::nullopt, ServiceType::HTTPS},
        {"amazon", "http://checkip.amazonaws.com", "/", std::nullopt, std::nullopt, ServiceType::HTTP},
        {"amazon", "https://checkip.amazonaws.com", "/", std::nullopt, std::nullopt, ServiceType::HTTPS},
        {"akamai", "http://whatismyip.akamai.com", "/", std::nullopt, std::nullopt, ServiceType::HTTP},
        {"akamai", "https://whatismyip.akamai.com", "/", std::nullopt, std::nullopt, ServiceType::HTTPS},
        {"ipinfo", "http://ipinfo.io", "/ip", std::nullopt, std::nullopt, ServiceType::HTTP},
        {"ipinfo", "https://ipinfo.io", "/ip", std::nullopt, std::nullopt, ServiceType::HTTPS},
        {"ipify", "http://api64.ipify.org", "/", std::nullopt, std::nullopt, ServiceType::HTTP},
        {"ipify", "https://api64.ipify.org", "/", std::nullopt, std::nullopt, ServiceType::HTTPS},
        {"opendns", "myip.opendns.com", std::nullopt, "resolver1.opendns.com", DNSProviderAcceptedQueryType::A_OR_AAAA, ServiceType::DNS},
        {"akamai-dns", "whoami.akamai.net", std::nullopt, "ns1-1.akamaitech.net", DNSProviderAcceptedQueryType::A_ONLY, ServiceType::DNS},
        {"google", "o-o.myaddr.l.google.com", std::nullopt, "ns1.google.com", DNSProviderAcceptedQueryType::TXT, ServiceType::DNS},
        {"quad9", "whatismyip.on.quad9.net", std::nullopt, "dns.quad9.net", DNSProviderAcceptedQueryType::A_OR_AAAA, ServiceType::DNS},
        {"akahelp", "whoami.ds.akahelp.net", std::nullopt, "a20-65.akam.net", DNSProviderAcceptedQueryType::TXT, ServiceType::DNS},
});
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (s.type == ServiceType::HTTP || s.type == ServiceType::HTTPS) return s.path.has_value(); else return true; }) );
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (s.type == ServiceType::DNS) return s.resolver.has_value(); else return true; }) );
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (s.type == ServiceType::DNS) return s.query_type.has_value(); else return true; }) );

asio::awaitable<std::expected<std::string, std::error_code>>
query_http_public_ip(fip::context& ctx, Service service)
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
    ctx.log.debug("Fetched current ip {} from {}", body, service.address);
    co_return std::string(body);
}

asio::awaitable<std::expected<std::string, std::error_code>>
query_public_ip(fip::context &ctx, Service service)
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
        ("n,name", "Ask only the named service and print its answer, without consensus", cxxopts::value<std::string>())
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

        std::optional<std::string> selectedName;

        if (result.count("name")) {
            selectedName = result["name"].as<std::string>();
            if (!std::ranges::contains(services, *selectedName, &Service::name)) {
                std::cerr << std::format("Unknown service '{}'. Choose from ", *selectedName);
                std::ranges::for_each(services
                                      | std::views::transform(&Service::name)
                                      | std::views::chunk_by(std::ranges::equal_to{})
                                      | std::views::transform([](const auto& names) { return names.front(); })
                                      | std::views::join_with(", "sv),
                                      [](const auto &c) {
                                          std::cerr << c;
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
        }) | std::views::filter([&selectedName](const auto& service) {
            return !selectedName || service.name == *selectedName;
        });
        auto candidates = std::ranges::to<std::vector<Service>>(filteredServices);
        if (candidates.empty()) {
            std::cerr << "No service matches the selected options\n";
            return EXIT_FAILURE;
        }

        fip::context ctx;
        ctx.requested_family = family;
        if (result.count("verbose")) {
            ctx.log.set_verbose(true);
        }

        // One service cannot reach consensus, so its answer stands on its own.
        if (selectedName) {
            const auto service = candidates.front();
            std::optional<std::string> answer;
            asio::co_spawn(ctx.io_context, query_public_ip(ctx, service),
                           [&](std::exception_ptr e, std::expected<std::string, std::error_code> result) {
                               if (e) std::rethrow_exception(e);
                               if (!result) {
                                   ctx.log.error("{} failed: {}", service.address, result.error().message());
                                   return;
                               }
                               answer = std::move(*result);
                           });
            ctx.io_context.run();
            if (!answer) {
                return EXIT_FAILURE;
            }
            std::cout << *answer << std::endl;
            return 0;
        }

        // Services are drawn from the back, so each is asked at most once.
        std::ranges::shuffle(candidates, ctx.rng);
        IPConsensus consensus;
        std::size_t in_flight = 0;
        std::optional<std::string> publicIp;

        struct Query {
            asio::cancellation_signal cancel;
            bool running = true;
        };
        // A list, since a signal cannot move while its query holds the slot.
        std::list<Query> queries;
        bool settled = false;
        // Stragglers can no longer change the outcome. A lookup already inside getaddrinfo still runs to completion.
        auto settle = [&] {
            settled = true;
            for (auto& query : queries) {
                if (query.running) {
                    query.cancel.emit(asio::cancellation_type::terminal);
                }
            }
        };

        auto top_up = [&](this auto& self) -> void {
            const auto needed = consensus.needed();
            if (in_flight + candidates.size() < needed) {
                ctx.log.error("No consensus from {} answers, {} in flight and {} services left", consensus.answers(), in_flight, candidates.size());
                settle();
                return;
            }
            for (; in_flight < needed; ++in_flight) {
                const auto service = candidates.back();
                candidates.pop_back();
                auto* query = &queries.emplace_back();
                asio::co_spawn(ctx.io_context, query_public_ip(ctx, service),
                               asio::bind_cancellation_slot(query->cancel.slot(),
                               [&, service, query](std::exception_ptr e, std::expected<std::string, std::error_code> result) {
                                   query->running = false;
                                   --in_flight;
                                   // A cancelled query unwinds by throwing operation_aborted from its next co_await.
                                   if (settled) {
                                       return;
                                   }
                                   if (e) std::rethrow_exception(e);
                                   if (result && !consensus.record(*result)) {
                                       ctx.log.debug("{} did not answer with an address: {}", service.address, *result);
                                   }
                                   if (auto winner = consensus.winner()) {
                                       ctx.log.notice("{} of {} answers agreed on {}", consensus.votes_for(*winner), consensus.answers(), *winner);
                                       publicIp = std::move(winner);
                                       settle();
                                       return;
                                   }
                                   self();
                               }));
            }
        };
        top_up();
        ctx.io_context.run();
        if (publicIp) {
            std::cout << *publicIp << std::endl;
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
