#include <format>
#include <string>
#include <string_view>
#include <boost/ut.hpp>
#include "log.hpp"

struct probe {
    int* formatted;
};

template <>
struct std::formatter<probe> : std::formatter<std::string_view> {
    auto format(const probe& p, std::format_context& ctx) const {
        ++*p.formatted;
        return std::formatter<std::string_view>::format("probe", ctx);
    }
};

int main() {
    using namespace boost::ut;

    "debug without a sink is not formatted"_test = [] {
        int formatted = 0;
        fip::logger log {true};
        log.debug("{}", probe {&formatted});
        expect(formatted == 0_i);
    };

    "info without a sink is not formatted"_test = [] {
        int formatted = 0;
        fip::logger log {true};
        log.info("{}", probe {&formatted});
        expect(formatted == 0_i);
    };

    "hook_print receives the formatted message"_test = [] {
        int formatted = 0;
        std::string printed;
        fip::logger log {true};
        log.hook_print = [&](const std::string_view& msg) { printed = msg; };
        log.debug("got {}", probe {&formatted});
        expect(formatted == 1_i);
        expect(printed == "got probe");
    };

    "verbose formats the message"_test = [] {
        int formatted = 0;
        fip::logger log {true};
        log.set_verbose(true);
        log.debug("{}", probe {&formatted});
        expect(formatted == 1_i);
    };
}
