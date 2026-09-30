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
        IPConsensus c {AddressFamily::Any, Trust::Unverified};
        expect(c.needed(AddressFamily::V4) == 2uz);
        expect(c.needed(AddressFamily::V6) == 2uz);
        expect(!c.winner().has_value());
    };

    "answer sequences"_test = [] (const std::vector<step>& steps) {
        IPConsensus c {AddressFamily::Any, Trust::Unverified};
        for (const auto& s : steps) {
            expect(c.record(s.answer, Trust::Unverified)) << s.answer;
            expect(c.needed(AddressFamily::V4) == s.v4_needed) << "IPv4 after" << s.answer;
            expect(c.needed(AddressFamily::V6) == s.v6_needed) << "IPv6 after" << s.answer;
            expect(c.winner().transform([](const auto& w) { return w.address; }) == s.winner) << "after" << s.answer;
        }
    } | std::vector<std::vector<step>> {
        // One answer is a majority of one but short of the two-answer quorum; a second agreeing answer wins.
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
        IPConsensus c {requested, Trust::Unverified};
        for (const auto host : {"1"sv, "2"sv, "3"sv, "4"sv}) {
            expect(c.record(std::string(mine) + std::string(host), Trust::Unverified));
        }
        expect(c.needed(requested) == 3uz);
        expect(c.needed(other) == std::nullopt);
        expect(c.record(std::string(theirs) + "9", Trust::Unverified));
        expect(c.record(std::string(theirs) + "9", Trust::Unverified));
        expect(!c.winner().has_value());
        expect(c.needed(requested) == 3uz);
        expect(c.needed(other) == std::nullopt);
        expect(eq(c.answers(), 6u));
    } | std::vector {AddressFamily::V4, AddressFamily::V6};

    "any is never a family that can win"_test = [] (AddressFamily requested) {
        IPConsensus c {requested, Trust::Unverified};
        expect(c.needed(AddressFamily::Any) == std::nullopt);
        expect(c.record("192.0.2.1", Trust::Unverified));
        expect(c.record("2001:db8::1", Trust::Unverified));
        expect(c.needed(AddressFamily::Any) == std::nullopt);
    } | std::vector {AddressFamily::Any, AddressFamily::V4, AddressFamily::V6};

    "a single-stack host leaves the other family at two"_test = [] {
        IPConsensus c {AddressFamily::Any, Trust::Unverified};
        for (const auto answer : {"1.1.1.1"sv, "2.2.2.2"sv, "3.3.3.3"sv, "4.4.4.4"sv}) {
            expect(c.record(answer, Trust::Unverified));
        }
        expect(c.needed(AddressFamily::V4) == 3uz);
        expect(c.needed(AddressFamily::V6) == 2uz);
        expect(!c.winner().has_value());
    };

    "a winner's majority is of its own family"_test = [] {
        IPConsensus c {AddressFamily::Any, Trust::Unverified};
        for (const auto answer : {"2001:db8::1"sv, "192.0.2.1"sv, "2001:db8::2"sv, "2001:db8::3"sv, "192.0.2.1"sv}) {
            expect(c.record(answer, Trust::Unverified));
        }
        expect(eq(c.answers(), 5u));
        expect(c.winner() == IPConsensus::Winner {"192.0.2.1", 2, 2});
    };

    "ipv6 spellings agree"_test = [] {
        IPConsensus c {AddressFamily::Any, Trust::Unverified};
        expect(c.record("2001:DB8::1", Trust::Unverified));
        expect(c.record("2001:db8:0:0::1", Trust::Unverified));
        expect(c.winner() == IPConsensus::Winner {"2001:db8::1", 2, 2});
    };

    "v4 and v6 are different answers"_test = [] {
        IPConsensus c {AddressFamily::Any, Trust::Unverified};
        expect(c.record("192.0.2.1", Trust::Unverified));
        expect(c.record("::ffff:192.0.2.1", Trust::Unverified));
        expect(!c.winner().has_value());
        expect(c.needed(AddressFamily::V4) == 1uz);
        expect(c.needed(AddressFamily::V6) == 1uz);
    };

    "non addresses are not counted"_test = [] (std::string_view text) {
        IPConsensus c {AddressFamily::Any, Trust::Unverified};
        expect(!c.record(text, Trust::Unverified)) << text;
        expect(eq(c.answers(), 0u));
    } | std::vector<std::string_view> {"", "example.com"sv, "1.2.3"sv, "1.2.3.4 "sv, "::g"sv};

    "a majority waits for a vote at the required trust"_test = [] (Trust needs) {
        IPConsensus c {AddressFamily::Any, needs};
        expect(c.record("192.0.2.1", Trust::Unverified));
        expect(c.record("192.0.2.1", Trust::Unverified));
        expect(!c.winner().has_value());
        expect(c.needed(AddressFamily::V4) == 1uz);
        expect(c.needs_trusted(AddressFamily::V4));
        expect(c.record("192.0.2.1", needs));
        expect(c.winner() == IPConsensus::Winner {"192.0.2.1", 3, 3});
        expect(!c.needs_trusted(AddressFamily::V4));
    } | std::vector {Trust::Authoritative, Trust::Authenticated};

    "a weaker trust does not satisfy a stronger requirement"_test = [] {
        IPConsensus c {AddressFamily::Any, Trust::Authenticated};
        expect(c.record("192.0.2.1", Trust::Authoritative));
        expect(c.record("192.0.2.1", Trust::Authoritative));
        expect(!c.winner().has_value());
        expect(c.needs_trusted(AddressFamily::V4));
    };

    "a stronger trust satisfies a weaker requirement"_test = [] {
        IPConsensus c {AddressFamily::Any, Trust::Authoritative};
        expect(c.record("192.0.2.1", Trust::Unverified));
        expect(c.record("192.0.2.1", Trust::Authenticated));
        expect(c.winner() == IPConsensus::Winner {"192.0.2.1", 2, 2});
    };

    "a trusted vote for another address does not confirm the leader"_test = [] {
        IPConsensus c {AddressFamily::Any, Trust::Authenticated};
        expect(c.record("192.0.2.1", Trust::Unverified));
        expect(c.record("192.0.2.1", Trust::Unverified));
        expect(c.record("198.51.100.1", Trust::Authenticated));
        expect(!c.winner().has_value());
        expect(c.needs_trusted(AddressFamily::V4));
    };

    "an empty tally needs a trusted vote only when one is required"_test = [] {
        IPConsensus required {AddressFamily::Any, Trust::Authenticated};
        expect(required.needs_trusted(AddressFamily::V4));
        expect(required.needs_trusted(AddressFamily::V6));
        expect(required.needed(AddressFamily::V4) == 2uz);

        IPConsensus not_required {AddressFamily::Any, Trust::Unverified};
        expect(!not_required.needs_trusted(AddressFamily::V4));
        expect(!not_required.needs_trusted(AddressFamily::V6));
    };

    "a family the run can't print never needs a trusted vote"_test = [] {
        IPConsensus c {AddressFamily::V4, Trust::Authenticated};
        expect(c.needs_trusted(AddressFamily::V4));
        expect(!c.needs_trusted(AddressFamily::V6));
    };
}
