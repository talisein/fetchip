#pragma once

#include <algorithm>
#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "address_family.hpp"
#include "dns.hpp"

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

// Whether the server a DNS service asks is the authority for its name, or a public resolver answering it.
enum class NameserverRole {
    Authoritative,
    Recursive,
};

struct Nameserver {
    std::string_view host;
    NameserverRole role;
};

struct Service {
    // Shared by the HTTP and HTTPS entries for one provider, which -i picks between, and by the DNS_A and DNS_AAAA entries, which -4 or -6 picks between.
    std::string_view name;
    std::string_view address;
    std::optional<std::string_view> path;
    std::optional<Nameserver> resolver;
    ServiceType type;
};

inline constexpr auto services = std::to_array<Service>({
        {"ifconfig.me", "http://ifconfig.me",            "/ip",        std::nullopt,            ServiceType::HTTP},
        {"ifconfig.me", "https://ifconfig.me",           "/ip",        std::nullopt,            ServiceType::HTTPS},
        {"icanhazip",   "http://icanhazip.com",          "/",          std::nullopt,            ServiceType::HTTP},
        {"icanhazip",   "https://icanhazip.com",         "/",          std::nullopt,            ServiceType::HTTPS},
        {"ipecho",      "http://ipecho.net",             "/plain",     std::nullopt,            ServiceType::HTTP},
        {"ipecho",      "https://ipecho.net",            "/plain",     std::nullopt,            ServiceType::HTTPS},
        {"ident.me",    "http://ident.me",               "/",          std::nullopt,            ServiceType::HTTP},
        {"ident.me",    "https://ident.me",              "/",          std::nullopt,            ServiceType::HTTPS},
        {"dnsomatic",   "http://myip.dnsomatic.com",     "/",          std::nullopt,            ServiceType::HTTP},
        {"dnsomatic",   "https://myip.dnsomatic.com",    "/",          std::nullopt,            ServiceType::HTTPS},
        {"amazon",      "http://checkip.amazonaws.com",  "/",          std::nullopt,            ServiceType::HTTP},
        {"amazon",      "https://checkip.amazonaws.com", "/",          std::nullopt,            ServiceType::HTTPS},
        {"akamai",      "http://whatismyip.akamai.com",  "/",          std::nullopt,            ServiceType::HTTP},
        {"akamai",      "https://whatismyip.akamai.com", "/",          std::nullopt,            ServiceType::HTTPS},
        {"ipinfo",      "http://ipinfo.io",              "/ip",        std::nullopt,            ServiceType::HTTP},
        {"ipinfo",      "https://ipinfo.io",             "/ip",        std::nullopt,            ServiceType::HTTPS},
        {"ipify",       "http://api64.ipify.org",        "/",          std::nullopt,            ServiceType::HTTP},
        {"ipify",       "https://api64.ipify.org",       "/",          std::nullopt,            ServiceType::HTTPS},
        {"opendns",     "myip.opendns.com",              std::nullopt, Nameserver {"resolver1.opendns.com", NameserverRole::Recursive},     ServiceType::DNS_A},
        {"opendns",     "myip.opendns.com",              std::nullopt, Nameserver {"resolver1.opendns.com", NameserverRole::Recursive},     ServiceType::DNS_AAAA},
        {"akamai-dns",  "whoami.akamai.net",             std::nullopt, Nameserver {"ns1-1.akamaitech.net",  NameserverRole::Authoritative}, ServiceType::DNS_A},
        {"google",      "o-o.myaddr.l.google.com",       std::nullopt, Nameserver {"ns1.google.com",        NameserverRole::Authoritative}, ServiceType::DNS_TXT},
        {"quad9",       "whatismyip.on.quad9.net",       std::nullopt, Nameserver {"dns.quad9.net",         NameserverRole::Recursive},     ServiceType::DNS_A},
        {"quad9",       "whatismyip.on.quad9.net",       std::nullopt, Nameserver {"dns.quad9.net",         NameserverRole::Recursive},     ServiceType::DNS_AAAA},
        {"akahelp",     "whoami.ds.akahelp.net",         std::nullopt, Nameserver {"a20-65.akam.net",       NameserverRole::Authoritative}, ServiceType::DNS_TXT},
});
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (s.type == ServiceType::HTTP || s.type == ServiceType::HTTPS) return s.path.has_value(); else return true; }) );
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (dns_query_type(s.type)) return s.resolver.has_value(); else return true; }) );
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (dns_query_type(s.type)) return validate_dns_name(s.address).has_value(); else return true; }) );

// DNS_A and DNS_AAAA services answer in their query's family; the others answer in whichever family connected.
bool serves_family(const Service& service, fip::AddressFamily family);

// What -s accepts: DNS for every DNS_* type, then each type by name.
std::vector<std::string_view> service_type_names();

// What -n accepts. Entries sharing a name are adjacent in services.
std::vector<std::string_view> service_names();

struct Selection {
    std::optional<ServiceType> type;
    bool dns = false;
    std::optional<std::string> name;
    fip::AddressFamily family = fip::AddressFamily::Any;
    bool insecure = false;
};

std::vector<Service> select_candidates(const Selection& selection);
