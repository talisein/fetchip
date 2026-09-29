#include <iostream>
#include <cerrno>
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
#include <functional>
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
#include "name_resolver.hpp"

using namespace std::literals;
enum class ServiceType {
    HTTP,
    HTTPS,
    DNS_A,
    DNS_AAAA,
    DNS_TXT,
};

// The wire query a DNS service sends, or nullopt for an HTTP one.
constexpr std::optional<DNSQueryType> dns_query_type(ServiceType type)
{
    switch (type) {
    case ServiceType::DNS_A:
        return DNSQueryType::A;
    case ServiceType::DNS_AAAA:
        return DNSQueryType::AAAA;
    case ServiceType::DNS_TXT:
        return DNSQueryType::TXT;
    case ServiceType::HTTP:
    case ServiceType::HTTPS:
        break;
    }
    return std::nullopt;
}

// What host_to_dnshost encodes: labels of at most 63 octets in a name of at most 253 text characters.
constexpr bool is_dns_name(std::string_view name)
{
    return name.size() <= 253
        && std::ranges::all_of(std::views::split(name, "."sv), [](const auto& label) { return std::ranges::size(label) <= 63; });
}

struct Service {
    // Shared by the HTTP and HTTPS entries for one provider, which -i picks between, and by the DNS_A and DNS_AAAA entries, which -4 or -6 picks between.
    std::string_view name;
    std::string_view address;
    std::optional<std::string_view> path;
    std::optional<std::string_view> resolver;
    ServiceType type;
};

constexpr auto services = std::to_array<Service>({
        {"ifconfig.me", "http://ifconfig.me", "/ip", std::nullopt, ServiceType::HTTP},
        {"ifconfig.me", "https://ifconfig.me", "/ip", std::nullopt, ServiceType::HTTPS},
        {"icanhazip", "http://icanhazip.com", "/", std::nullopt, ServiceType::HTTP},
        {"icanhazip", "https://icanhazip.com", "/", std::nullopt, ServiceType::HTTPS},
        {"ipecho", "http://ipecho.net", "/plain", std::nullopt, ServiceType::HTTP},
        {"ipecho", "https://ipecho.net", "/plain", std::nullopt, ServiceType::HTTPS},
        {"ident.me", "http://ident.me", "/", std::nullopt, ServiceType::HTTP},
        {"ident.me", "https://ident.me", "/", std::nullopt, ServiceType::HTTPS},
        {"dnsomatic", "http://myip.dnsomatic.com", "/", std::nullopt, ServiceType::HTTP},
        {"dnsomatic", "https://myip.dnsomatic.com", "/", std::nullopt, ServiceType::HTTPS},
        {"amazon", "http://checkip.amazonaws.com", "/", std::nullopt, ServiceType::HTTP},
        {"amazon", "https://checkip.amazonaws.com", "/", std::nullopt, ServiceType::HTTPS},
        {"akamai", "http://whatismyip.akamai.com", "/", std::nullopt, ServiceType::HTTP},
        {"akamai", "https://whatismyip.akamai.com", "/", std::nullopt, ServiceType::HTTPS},
        {"ipinfo", "http://ipinfo.io", "/ip", std::nullopt, ServiceType::HTTP},
        {"ipinfo", "https://ipinfo.io", "/ip", std::nullopt, ServiceType::HTTPS},
        {"ipify", "http://api64.ipify.org", "/", std::nullopt, ServiceType::HTTP},
        {"ipify", "https://api64.ipify.org", "/", std::nullopt, ServiceType::HTTPS},
        {"opendns", "myip.opendns.com", std::nullopt, "resolver1.opendns.com", ServiceType::DNS_A},
        {"opendns", "myip.opendns.com", std::nullopt, "resolver1.opendns.com", ServiceType::DNS_AAAA},
        {"akamai-dns", "whoami.akamai.net", std::nullopt, "ns1-1.akamaitech.net", ServiceType::DNS_A},
        {"google", "o-o.myaddr.l.google.com", std::nullopt, "ns1.google.com", ServiceType::DNS_TXT},
        {"quad9", "whatismyip.on.quad9.net", std::nullopt, "dns.quad9.net", ServiceType::DNS_A},
        {"quad9", "whatismyip.on.quad9.net", std::nullopt, "dns.quad9.net", ServiceType::DNS_AAAA},
        {"akahelp", "whoami.ds.akahelp.net", std::nullopt, "a20-65.akam.net", ServiceType::DNS_TXT},
});
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (s.type == ServiceType::HTTP || s.type == ServiceType::HTTPS) return s.path.has_value(); else return true; }) );
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (dns_query_type(s.type)) return s.resolver.has_value(); else return true; }) );
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (dns_query_type(s.type)) return is_dns_name(s.address); else return true; }) );

// DNS_A and DNS_AAAA services answer in their query's family; the others answer in whichever family connected.
bool serves_family(const Service& service, fip::AddressFamily family)
{
    const auto dns_query = dns_query_type(service.type);
    return !dns_query || query_answers_family(*dns_query, family);
}

// What -s accepts: DNS for every DNS_* type, then each type by name.
std::vector<std::string_view> service_type_names()
{
    std::vector<std::string_view> names {"DNS"};
    std::ranges::copy(magic_enum::enum_names<ServiceType>(), std::back_inserter(names));
    return names;
}

// What -n accepts. Entries sharing a name are adjacent in services.
std::vector<std::string_view> service_names()
{
    return services
        | std::views::transform(&Service::name)
        | std::views::chunk_by(std::ranges::equal_to{})
        | std::views::transform([](const auto& names) { return names.front(); })
        | std::ranges::to<std::vector>();
}

asio::awaitable<std::expected<std::string, std::error_code>>
query_http_public_ip(fip::context& ctx, Service service)
{
    auto res = co_await http_get(ctx, service.address, *service.path);
    if (!res) {
        ctx.log.debug("Failed to fetch ip from {}: {}", service.address, res.error().message());
        co_return std::unexpected(res.error());
    }
    const auto is_space = [](char c) { return " \t\r\n"sv.contains(c); };
    auto body = *res | std::views::reverse | std::views::drop_while(is_space) | std::views::reverse | std::ranges::to<std::string>();
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
    co_return body;
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

void log_exception(fip::context& ctx, std::string_view who, std::exception_ptr e)
{
    try { std::rethrow_exception(e); }
    catch (const std::exception& ex) {
        ctx.log.error("{} failed: {}", who, ex.what());
    }
    catch (...) {
        ctx.log.error("{} failed with an unknown exception", who);
    }
}

int main(int argc, char* argv[]) {
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
            return 0;
        }

        if (result.count("list")) {
            const auto list = result["list"].as<std::string>();
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
            return 0;
        }

        std::optional<ServiceType> selectedType;
        // -s DNS selects every DNS_* type.
        bool selectedDNS = false;

        if (result.count("service")) {
            const auto service = result["service"].as<std::string>();
            selectedDNS = std::ranges::equal(service, "DNS"sv, {}, [](unsigned char c) { return std::toupper(c); });
            selectedType = magic_enum::enum_cast<ServiceType>(service, magic_enum::case_insensitive);
            if (!selectedDNS && !selectedType) {
                std::cerr << std::format("Unknown service type '{}'. Choose from ", service);
                std::ranges::for_each(service_type_names()
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
                std::ranges::for_each(service_names()
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

        // -s HTTP explicitly asks for plain HTTP, so it implies -i.
        auto use_secure = !result["insecure"].as<bool>()
                          && selectedType != ServiceType::HTTP;
        auto secureServices = std::views::filter(services, [use_secure](const auto &service) {
            if (use_secure && service.type == ServiceType::HTTP)
                return false;
            if (!use_secure && service.type == ServiceType::HTTPS)
                return false;
            return true;
        });
        auto filteredServices = std::ranges::views::filter(secureServices, [selectedType, selectedDNS](const auto& service) {
            if (selectedDNS) {
                return dns_query_type(service.type).has_value();
            } else if (selectedType) {
                return service.type == *selectedType;
            } else {
                return true;
            }
        }) | std::views::filter([family](const auto& service) {
            return serves_family(service, family);
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

        if (const auto ec = connect_resolved(ctx.io_context); ec != boost::system::error_code {}) {
            std::cerr << std::format("systemd-resolved is required to use this program: cannot connect to {} ({})\n", fip::resolved_address, ec.message());
            return EXIT_FAILURE;
        }

        // One service cannot reach consensus, so its answer stands on its own.
        // A name can have several entries (say, DNS_A and DNS_AAAA); try each
        // in turn and print the first answer.
        if (selectedName) {
            std::optional<std::string> answer;
            asio::co_spawn(ctx.io_context,
                           [&]() -> asio::awaitable<void> {
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
                                   answer = address.to_string();
                                   co_return;
                               }
                           },
                           [&](std::exception_ptr e) {
                               if (e) {
                                   log_exception(ctx, *selectedName, e);
                               }
                           });
            ctx.io_context.run();
            if (!answer) {
                return EXIT_FAILURE;
            }
            if (const auto printed = print_line(*answer); !printed) {
                ctx.log.error("Cannot write {} to stdout: {}", *answer, printed.error().message());
                return EXIT_FAILURE;
            }
            return 0;
        }

        // Services are drawn from the back, so each is asked at most once.
        std::ranges::shuffle(candidates, ctx.rng);
        IPConsensus consensus {family};
        std::optional<std::string> publicIp;

        struct Query {
            Service service;
            asio::cancellation_signal cancel;
            bool running = true;
        };
        // A list, since a signal cannot move while its query holds the slot.
        std::list<Query> queries;
        auto in_flight = [&](fip::AddressFamily family) {
            return static_cast<std::size_t>(std::ranges::count_if(queries, [family](const Query& query) {
                return query.running && serves_family(query.service, family);
            }));
        };
        auto left = [&](fip::AddressFamily family) {
            return static_cast<std::size_t>(std::ranges::count_if(candidates, std::bind_back(serves_family, family)));
        };
        bool settled = false;
        // Stragglers can no longer change the outcome.
        auto settle = [&] {
            settled = true;
            for (auto& query : queries) {
                if (query.running) {
                    query.cancel.emit(asio::cancellation_type::terminal);
                }
            }
        };

        auto top_up = [&](this auto& self) -> void {
            // Only services that can answer in a family can vote in it, so a family stays open while
            // enough of them are in flight or left. Every open family is kept topped up, so whichever
            // wins first is printed.
            bool open = false;
            for (const auto family : {fip::AddressFamily::V4, fip::AddressFamily::V6}) {
                const auto needed = consensus.needed(family);
                if (!needed || in_flight(family) + left(family) < *needed) {
                    continue;
                }
                open = true;
                while (in_flight(family) < *needed) {
                    const auto next = std::ranges::find_last_if(candidates, std::bind_back(serves_family, family)).begin();
                    if (next == candidates.end()) {
                        break;
                    }
                    const auto service = *next;
                    candidates.erase(next);
                    auto* query = &queries.emplace_back(service);
                    asio::co_spawn(ctx.io_context, query_public_ip(ctx, service),
                                   asio::bind_cancellation_slot(query->cancel.slot(),
                                   [&, service, query](std::exception_ptr e, std::expected<std::string, std::error_code> result) {
                                       query->running = false;
                                       // A cancelled query unwinds by throwing operation_aborted from its next co_await.
                                       if (settled) {
                                           return;
                                       }
                                       // One failed query is one lost vote, never the whole run.
                                       if (e) {
                                           log_exception(ctx, service.address, e);
                                           self();
                                           return;
                                       }
                                       if (result && !consensus.record(*result)) {
                                           ctx.log.debug("{} did not answer with an address: {}", service.address, *result);
                                       }
                                       if (auto winner = consensus.winner()) {
                                           ctx.log.notice("{} of {} answers agreed on {}", winner->votes, winner->answers, winner->address);
                                           publicIp = std::move(winner->address);
                                           settle();
                                           return;
                                       }
                                       self();
                                   }));
                }
            }
            if (!open) {
                ctx.log.error("No consensus from {} answers, {} in flight and {} services left", consensus.answers(), std::ranges::count(queries, true, &Query::running), candidates.size());
                settle();
            }
        };
        top_up();
        ctx.io_context.run();
        if (!publicIp) {
            return EXIT_FAILURE;
        }
        if (const auto printed = print_line(*publicIp); !printed) {
            ctx.log.error("Cannot write {} to stdout: {}", *publicIp, printed.error().message());
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
