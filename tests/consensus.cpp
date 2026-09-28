#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <boost/ut.hpp>
#include "consensus.hpp"

struct step {
    std::string_view answer;
    std::size_t needed;
    std::optional<std::string> winner;
};

int main() {
    using namespace boost::ut;
    using namespace std::string_literals;
    using namespace std::string_view_literals;

    "nothing recorded"_test = [] {
        IPConsensus c;
        expect(eq(c.needed(), 2u));
        expect(!c.winner().has_value());
    };

    "answer sequences"_test = [] (const std::vector<step>& steps) {
        IPConsensus c;
        for (const auto& s : steps) {
            expect(c.record(s.answer)) << s.answer;
            expect(eq(c.needed(), s.needed)) << "after" << s.answer;
            expect(c.winner() == s.winner) << "after" << s.answer;
        }
    } | std::vector<std::vector<step>> {
        {{"1.1.1.1", 1, {}}, {"1.1.1.1", 0, "1.1.1.1"s}},
        {{"1.1.1.1", 1, {}}, {"2.2.2.2", 1, {}}, {"1.1.1.1", 0, "1.1.1.1"s}},
        {{"1.1.1.1", 1, {}}, {"2.2.2.2", 1, {}}, {"3.3.3.3", 2, {}}, {"2.2.2.2", 1, {}}, {"2.2.2.2", 0, "2.2.2.2"s}},
        {{"1.1.1.1", 1, {}}, {"2.2.2.2", 1, {}}, {"3.3.3.3", 2, {}}, {"1.1.1.1", 1, {}}, {"4.4.4.4", 2, {}}},
    };

    "ipv6 spellings agree"_test = [] {
        IPConsensus c;
        expect(c.record("2001:DB8::1"));
        expect(c.record("2001:db8:0:0::1"));
        expect(c.winner() == "2001:db8::1"s);
    };

    "v4 and v6 are different answers"_test = [] {
        IPConsensus c;
        expect(c.record("192.0.2.1"));
        expect(c.record("::ffff:192.0.2.1"));
        expect(!c.winner().has_value());
        expect(eq(c.needed(), 1u));
    };

    "non addresses are not counted"_test = [] (std::string_view text) {
        IPConsensus c;
        expect(!c.record(text)) << text;
        expect(eq(c.answers(), 0u));
    } | std::vector<std::string_view> {"", "example.com"sv, "1.2.3"sv, "1.2.3.4 "sv, "::g"sv};
}
