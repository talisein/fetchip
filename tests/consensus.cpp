#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <boost/ut.hpp>
#include "consensus.hpp"

using fip::AddressFamily;

struct step {
    std::string_view answer;
    std::size_t v4_needed;
    std::size_t v6_needed;
    std::optional<std::string> winner;
};

int main() {
    using namespace boost::ut;
    using namespace std::string_literals;
    using namespace std::string_view_literals;

    "nothing recorded"_test = [] {
        IPConsensus c {AddressFamily::Any};
        expect(c.needed(AddressFamily::V4) == 2uz);
        expect(c.needed(AddressFamily::V6) == 2uz);
        expect(!c.winner().has_value());
    };

    "answer sequences"_test = [] (const std::vector<step>& steps) {
        IPConsensus c {AddressFamily::Any};
        for (const auto& s : steps) {
            expect(c.record(s.answer)) << s.answer;
            expect(c.needed(AddressFamily::V4) == s.v4_needed) << "IPv4 after" << s.answer;
            expect(c.needed(AddressFamily::V6) == s.v6_needed) << "IPv6 after" << s.answer;
            expect(c.winner().transform([](const auto& w) { return w.address; }) == s.winner) << "after" << s.answer;
        }
    } | std::vector<std::vector<step>> {
        {{"1.1.1.1", 1, 2, {}}, {"1.1.1.1", 0, 2, "1.1.1.1"s}},
        {{"1.1.1.1", 1, 2, {}}, {"2.2.2.2", 1, 2, {}}, {"1.1.1.1", 0, 2, "1.1.1.1"s}},
        {{"1.1.1.1", 1, 2, {}}, {"2.2.2.2", 1, 2, {}}, {"3.3.3.3", 2, 2, {}}, {"2.2.2.2", 1, 2, {}}, {"2.2.2.2", 0, 2, "2.2.2.2"s}},
        {{"1.1.1.1", 1, 2, {}}, {"2.2.2.2", 1, 2, {}}, {"3.3.3.3", 2, 2, {}}, {"1.1.1.1", 1, 2, {}}, {"4.4.4.4", 2, 2, {}}},
        // Four IPv4 answers that disagree need three more for a majority; the empty IPv6 tally doesn't lower that.
        {{"1.1.1.1", 1, 2, {}}, {"2.2.2.2", 1, 2, {}}, {"3.3.3.3", 2, 2, {}}, {"4.4.4.4", 3, 2, {}}},
        // A dual-stack host: each family is its own vote.
        {{"192.0.2.1", 1, 2, {}}, {"2001:db8::1", 1, 1, {}}, {"192.0.2.1", 0, 1, "192.0.2.1"s}},
        {{"2001:db8::1", 2, 1, {}}, {"192.0.2.1", 1, 1, {}}, {"2001:db8::1", 1, 0, "2001:db8::1"s}},
        // An IPv4 disagreement doesn't hold back IPv6.
        {{"1.1.1.1", 1, 2, {}}, {"2.2.2.2", 1, 2, {}}, {"2001:db8::1", 1, 1, {}}, {"2001:db8::1", 1, 0, "2001:db8::1"s}},
    };

    "a single family never consults the other"_test = [] (AddressFamily requested) {
        const auto other = requested == AddressFamily::V4 ? AddressFamily::V6 : AddressFamily::V4;
        const auto [mine, theirs] = requested == AddressFamily::V4 ? std::pair {"192.0.2."sv, "2001:db8::"sv} : std::pair {"2001:db8::"sv, "192.0.2."sv};
        IPConsensus c {requested};
        for (const auto host : {"1"sv, "2"sv, "3"sv, "4"sv}) {
            expect(c.record(std::string(mine) + std::string(host)));
        }
        expect(c.needed(requested) == 3uz);
        expect(c.needed(other) == std::nullopt);
        expect(c.record(std::string(theirs) + "9"));
        expect(c.record(std::string(theirs) + "9"));
        expect(!c.winner().has_value());
        expect(c.needed(requested) == 3uz);
        expect(c.needed(other) == std::nullopt);
        expect(eq(c.answers(), 6u));
    } | std::vector {AddressFamily::V4, AddressFamily::V6};

    "any is never a family that can win"_test = [] (AddressFamily requested) {
        IPConsensus c {requested};
        expect(c.needed(AddressFamily::Any) == std::nullopt);
        expect(c.record("192.0.2.1"));
        expect(c.record("2001:db8::1"));
        expect(c.needed(AddressFamily::Any) == std::nullopt);
    } | std::vector {AddressFamily::Any, AddressFamily::V4, AddressFamily::V6};

    "a single-stack host leaves the other family at two"_test = [] {
        IPConsensus c {AddressFamily::Any};
        for (const auto answer : {"1.1.1.1"sv, "2.2.2.2"sv, "3.3.3.3"sv, "4.4.4.4"sv}) {
            expect(c.record(answer));
        }
        expect(c.needed(AddressFamily::V4) == 3uz);
        expect(c.needed(AddressFamily::V6) == 2uz);
        expect(!c.winner().has_value());
    };

    "a winner's majority is of its own family"_test = [] {
        IPConsensus c {AddressFamily::Any};
        for (const auto answer : {"2001:db8::1"sv, "192.0.2.1"sv, "2001:db8::2"sv, "2001:db8::3"sv, "192.0.2.1"sv}) {
            expect(c.record(answer));
        }
        expect(eq(c.answers(), 5u));
        expect(c.winner() == IPConsensus::Winner {"192.0.2.1", 2, 2});
    };

    "ipv6 spellings agree"_test = [] {
        IPConsensus c {AddressFamily::Any};
        expect(c.record("2001:DB8::1"));
        expect(c.record("2001:db8:0:0::1"));
        expect(c.winner() == IPConsensus::Winner {"2001:db8::1", 2, 2});
    };

    "v4 and v6 are different answers"_test = [] {
        IPConsensus c {AddressFamily::Any};
        expect(c.record("192.0.2.1"));
        expect(c.record("::ffff:192.0.2.1"));
        expect(!c.winner().has_value());
        expect(c.needed(AddressFamily::V4) == 1uz);
        expect(c.needed(AddressFamily::V6) == 1uz);
    };

    "non addresses are not counted"_test = [] (std::string_view text) {
        IPConsensus c {AddressFamily::Any};
        expect(!c.record(text)) << text;
        expect(eq(c.answers(), 0u));
    } | std::vector<std::string_view> {"", "example.com"sv, "1.2.3"sv, "1.2.3.4 "sv, "::g"sv};
}
