#include <format>
#include <ios>
#include <string_view>
#include <system_error>
#include <boost/ut.hpp>
#include <magic_enum/magic_enum.hpp>
#include "dns.hpp"
#include "fetch_error.hpp"
#include "http_error.hpp"

static_assert(fip::fip_error<FetchError>);
static_assert(fip::fip_error<HTTPError>);
static_assert(fip::fip_error<DNSError>);
static_assert(!fip::fip_error<std::io_errc>);
static_assert(!fip::fip_error<std::errc>);

template <typename E>
void check_category(E value, std::string_view name) {
    using namespace boost::ut;

    const std::error_code ec = value;
    expect(eq(std::string_view(ec.category().name()), name));
    expect(eq(ec.message(), magic_enum::enum_name(value)));
    expect(ec == value);
    expect(&ec.category() == &fip::error_category<E>());
    expect(eq(ec.category().message(-1), std::format("Unknown {}", name)));
}

int main() {
    using namespace boost::ut;

    "FetchError category"_test = [] {
        check_category(FetchError::NameResolutionFailed, "FetchError");
    };

    "HTTPError category"_test = [] {
        check_category(HTTPError::UnexpectedStatus, "HTTPError");
    };

    "DNSError category"_test = [] {
        check_category(DNSError::DNSResolverMismatchedResponse, "DNSError");
    };

    "categories are distinct per enum"_test = [] {
        expect(fip::error_category<FetchError>() != fip::error_category<HTTPError>());
        expect(fip::error_category<HTTPError>() != fip::error_category<DNSError>());
        expect(make_error_code(FetchError::UnknownServiceType) != make_error_code(HTTPError::UnsupportedScheme));
    };
}
