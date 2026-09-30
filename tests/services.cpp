#include <algorithm>
#include <set>
#include <string_view>
#include <utility>
#include <vector>
#include <boost/ut.hpp>

#include "services.hpp"

using fip::AddressFamily;

std::size_t count_type(const std::vector<Service>& selected, ServiceType type)
{
    return static_cast<std::size_t>(std::ranges::count(selected, type, &Service::type));
}

std::size_t count_in_table(ServiceType type)
{
    return static_cast<std::size_t>(std::ranges::count(services, type, &Service::type));
}

int main() {
    using namespace boost::ut;
    using namespace std::string_view_literals;

    "default is HTTPS and every DNS type"_test = [] {
        const auto selected = select_candidates({});
        expect(count_type(selected, ServiceType::HTTP) == 0uz);
        expect(count_type(selected, ServiceType::HTTPS) == count_in_table(ServiceType::HTTPS));
        expect(count_type(selected, ServiceType::DNS_A) == count_in_table(ServiceType::DNS_A));
        expect(count_type(selected, ServiceType::DNS_AAAA) == count_in_table(ServiceType::DNS_AAAA));
        expect(count_type(selected, ServiceType::DNS_TXT) == count_in_table(ServiceType::DNS_TXT));
    };

    "-i swaps HTTPS for HTTP"_test = [] {
        const auto selected = select_candidates({.insecure = true});
        expect(count_type(selected, ServiceType::HTTP) == count_in_table(ServiceType::HTTP));
        expect(count_type(selected, ServiceType::HTTPS) == 0uz);
        expect(count_type(selected, ServiceType::DNS_A) == count_in_table(ServiceType::DNS_A));
    };

    "-s HTTP implies -i"_test = [] {
        const auto selected = select_candidates({.type = ServiceType::HTTP});
        expect(!selected.empty());
        expect(selected.size() == count_type(selected, ServiceType::HTTP));
    };

    "-s HTTPS with -i selects nothing"_test = [] {
        expect(select_candidates({.type = ServiceType::HTTPS, .insecure = true}).empty());
    };

    "-s DNS selects only DNS types"_test = [] {
        const auto selected = select_candidates({.dns = true});
        expect(!selected.empty());
        expect(std::ranges::all_of(selected, [](const Service& s) { return dns_query_type(s.type).has_value(); }));
        expect(selected.size() == count_in_table(ServiceType::DNS_A) + count_in_table(ServiceType::DNS_AAAA) + count_in_table(ServiceType::DNS_TXT));
    };

    "-4 drops AAAA and -6 drops A"_test = [] {
        const auto v4 = select_candidates({.family = AddressFamily::V4});
        expect(count_type(v4, ServiceType::DNS_AAAA) == 0uz);
        expect(count_type(v4, ServiceType::DNS_A) == count_in_table(ServiceType::DNS_A));
        expect(count_type(v4, ServiceType::DNS_TXT) == count_in_table(ServiceType::DNS_TXT));
        expect(count_type(v4, ServiceType::HTTPS) == count_in_table(ServiceType::HTTPS));

        const auto v6 = select_candidates({.family = AddressFamily::V6});
        expect(count_type(v6, ServiceType::DNS_A) == 0uz);
        expect(count_type(v6, ServiceType::DNS_AAAA) == count_in_table(ServiceType::DNS_AAAA));
        expect(count_type(v6, ServiceType::DNS_TXT) == count_in_table(ServiceType::DNS_TXT));
        expect(count_type(v6, ServiceType::HTTPS) == count_in_table(ServiceType::HTTPS));
    };

    "-n keeps every entry of the name"_test = [] {
        const auto any = select_candidates({.name = "opendns"});
        expect(fatal(any.size() == 2uz));
        expect(count_type(any, ServiceType::DNS_A) == 1uz);
        expect(count_type(any, ServiceType::DNS_AAAA) == 1uz);

        const auto v6 = select_candidates({.name = "opendns", .family = AddressFamily::V6});
        expect(fatal(v6.size() == 1uz));
        expect(v6.front().type == ServiceType::DNS_AAAA);
    };

    "-n with an HTTP provider picks the scheme from -i"_test = [] {
        const auto secure = select_candidates({.name = "ipinfo"});
        expect(fatal(secure.size() == 1uz));
        expect(secure.front().type == ServiceType::HTTPS);

        const auto insecure = select_candidates({.name = "ipinfo", .insecure = true});
        expect(fatal(insecure.size() == 1uz));
        expect(insecure.front().type == ServiceType::HTTP);
    };

    "service names are the distinct names in the table"_test = [] {
        const auto names = service_names();
        const std::set<std::string_view> unique_names(names.begin(), names.end());
        expect(unique_names.size() == names.size());
        const auto table_names = services | std::views::transform(&Service::name);
        const std::set<std::string_view> in_table(table_names.begin(), table_names.end());
        expect(unique_names == in_table);
    };

    "service type names start with DNS"_test = [] {
        const auto names = service_type_names();
        expect(fatal(!names.empty()));
        expect(names.front() == "DNS"sv);
        expect(std::ranges::contains(names, "DNS_TXT"sv));
    };
}
