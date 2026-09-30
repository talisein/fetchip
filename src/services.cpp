#include <functional>
#include <iterator>
#include <ranges>

#include <magic_enum/magic_enum.hpp>
#include "dns_resolver.hpp"
#include "services.hpp"

bool serves_family(const Service& service, fip::AddressFamily family)
{
    const auto dns_query = dns_query_type(service.type);
    return !dns_query || query_answers_family(*dns_query, family);
}

Trust trust_of(const Service& service)
{
    if (service.type == ServiceType::HTTPS) {
        return Trust::Authenticated;
    }
    if (service.resolver && service.resolver->role == NameserverRole::Authoritative) {
        return Trust::Authoritative;
    }
    return Trust::Unverified;
}

std::vector<std::string_view> service_type_names()
{
    std::vector<std::string_view> names {"DNS"};
    std::ranges::copy(magic_enum::enum_names<ServiceType>(), std::back_inserter(names));
    return names;
}

std::vector<std::string_view> service_names()
{
    return services
        | std::views::transform(&Service::name)
        | std::views::chunk_by(std::ranges::equal_to{})
        | std::views::transform([](const auto& names) { return names.front(); })
        | std::ranges::to<std::vector>();
}

std::vector<Service> select_candidates(const Selection& selection)
{
    // -s HTTP explicitly asks for plain HTTP, so it implies -i.
    const auto use_secure = !selection.insecure
                            && selection.type != ServiceType::HTTP;
    auto secureServices = std::views::filter(services, [use_secure](const auto &service) {
        if (use_secure && service.type == ServiceType::HTTP)
            return false;
        if (!use_secure && service.type == ServiceType::HTTPS)
            return false;
        return true;
    });
    auto filteredServices = std::ranges::views::filter(secureServices, [&selection](const auto& service) {
        if (selection.dns) {
            return dns_query_type(service.type).has_value();
        } else if (selection.type) {
            return service.type == *selection.type;
        } else {
            return true;
        }
    }) | std::views::filter([&selection](const auto& service) {
        return serves_family(service, selection.family);
    }) | std::views::filter([&selection](const auto& service) {
        return !selection.name || service.name == *selection.name;
    });
    return std::ranges::to<std::vector<Service>>(filteredServices);
}
