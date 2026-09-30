#include <algorithm>
#include <ranges>

#include "consensus.hpp"
#include "net.hpp"

namespace {
    // README: an address wins once at least two services report it.
    constexpr std::size_t min_agreeing_answers { 2 };

    std::optional<std::size_t> slot(fip::AddressFamily family)
    {
        switch (family) {
        case fip::AddressFamily::V4:
            return 0;
        case fip::AddressFamily::V6:
            return 1;
        case fip::AddressFamily::Any:
            break;
        }
        return std::nullopt;
    }
}

bool IPConsensus::record(std::string_view text, Trust trust)
{
    boost::system::error_code ec;
    auto address = asio::ip::make_address(text, ec);
    if (ec != boost::system::error_code {}) {
        return false;
    }
    auto tally = tally_for(fip::family_of(address));
    if (!tally) {
        return false;
    }
    // Canonical text, so different spellings of one IPv6 address agree.
    const auto canonical = address.to_string();
    auto& vote = tally->get().votes[canonical];
    ++vote.count;
    vote.strongest = std::max(vote.strongest, trust);
    ++tally->get().total;
    return true;
}

std::map<std::string, IPConsensus::Vote>::const_iterator IPConsensus::Tally::leader() const
{
    return std::ranges::max_element(votes, {}, [](const auto& entry) { return entry.second.count; });
}

std::size_t IPConsensus::Tally::leader_votes() const
{
    auto it = leader();
    return it == votes.end() ? 0 : it->second.count;
}

bool IPConsensus::Tally::leader_trusted(Trust needs) const
{
    if (needs == Trust::Unverified) {
        return true;
    }
    auto it = leader();
    return it != votes.end() && it->second.strongest >= needs;
}

std::optional<IPConsensus::Winner> IPConsensus::Tally::winner(Trust needs) const
{
    auto it = leader();
    if (it == votes.end()) {
        return std::nullopt;
    }
    const bool quorum = it->second.count >= min_agreeing_answers;
    const bool strict_majority = 2 * it->second.count > total;
    if (!quorum || !strict_majority || !leader_trusted(needs)) {
        return std::nullopt;
    }
    return Winner {it->first, it->second.count, total};
}

std::size_t IPConsensus::Tally::needed(Trust needs) const
{
    // k agreeing answers win when leader + k >= min_agreeing_answers (the quorum)
    // and 2 * (leader + k) > total + k (a strict majority), and one more is needed
    // when no vote for the leader is yet at the required trust.
    const auto leader = leader_votes();
    const std::size_t for_majority = total + 1 > 2 * leader ? total + 1 - 2 * leader : 0;
    const std::size_t for_quorum = leader < min_agreeing_answers ? min_agreeing_answers - leader : 0;
    const std::size_t for_trust = leader_trusted(needs) ? 0 : 1;
    return std::max({for_majority, for_quorum, for_trust});
}

std::optional<std::reference_wrapper<IPConsensus::Tally>> IPConsensus::tally_for(fip::AddressFamily family)
{
    return slot(family).transform([this](std::size_t i) { return std::ref(tallies[i]); });
}

std::optional<std::reference_wrapper<const IPConsensus::Tally>> IPConsensus::tally_for(fip::AddressFamily family) const
{
    return slot(family).transform([this](std::size_t i) { return std::cref(tallies[i]); });
}

std::optional<std::reference_wrapper<const IPConsensus::Tally>> IPConsensus::contender(fip::AddressFamily family) const
{
    // Under -4 or -6 the other family's answers can never be printed.
    if (requested != fip::AddressFamily::Any && family != requested) {
        return std::nullopt;
    }
    return tally_for(family);
}

std::size_t IPConsensus::answers() const
{
    return std::ranges::fold_left(tallies | std::views::transform(&Tally::total), std::size_t {0}, std::plus {});
}

std::optional<IPConsensus::Winner> IPConsensus::winner() const
{
    for (const auto family : {fip::AddressFamily::V4, fip::AddressFamily::V6}) {
        if (auto winner = contender(family).and_then([this](const Tally& t) { return t.winner(winner_needs); })) {
            return winner;
        }
    }
    return std::nullopt;
}

std::optional<std::size_t> IPConsensus::needed(fip::AddressFamily family) const
{
    return contender(family).transform([this](const Tally& t) { return t.needed(winner_needs); });
}

bool IPConsensus::needs_trusted(fip::AddressFamily family) const
{
    return contender(family).transform([this](const Tally& t) { return !t.leader_trusted(winner_needs); }).value_or(false);
}
