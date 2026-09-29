#include <algorithm>
#include <ranges>

#include "consensus.hpp"
#include "net.hpp"

bool IPConsensus::record(std::string_view text)
{
    boost::system::error_code ec;
    auto address = asio::ip::make_address(text, ec);
    if (ec != boost::system::error_code {}) {
        return false;
    }
    auto& tally = tallies[address.is_v6()];
    // Canonical text, so different spellings of one IPv6 address agree.
    ++tally.votes[address.to_string()];
    ++tally.total;
    return true;
}

std::map<std::string, std::size_t>::const_iterator IPConsensus::Tally::leader() const
{
    return std::ranges::max_element(std::views::values(votes)).base();
}

std::size_t IPConsensus::Tally::leader_votes() const
{
    auto it = leader();
    return it == votes.end() ? 0 : it->second;
}

std::optional<std::string> IPConsensus::Tally::winner() const
{
    auto it = leader();
    if (it == votes.end() || it->second < 2 || 2 * it->second <= total) {
        return std::nullopt;
    }
    return it->first;
}

std::size_t IPConsensus::Tally::needed() const
{
    // k agreeing answers win when leader + k >= 2 and 2 * (leader + k) > total + k.
    const auto leader = leader_votes();
    const std::size_t for_majority = total + 1 > 2 * leader ? total + 1 - 2 * leader : 0;
    const std::size_t for_pair = leader < 2 ? 2 - leader : 0;
    return std::max(for_majority, for_pair);
}

std::size_t IPConsensus::answers() const
{
    return std::ranges::fold_left(tallies | std::views::transform(&Tally::total), std::size_t {0}, std::plus {});
}

std::size_t IPConsensus::votes_for(const std::string& address) const
{
    for (const auto& tally : tallies) {
        if (auto it = tally.votes.find(address); it != tally.votes.end()) {
            return it->second;
        }
    }
    return 0;
}

std::optional<std::string> IPConsensus::winner() const
{
    for (const auto& tally : tallies) {
        if (auto winner = tally.winner()) {
            return winner;
        }
    }
    return std::nullopt;
}

std::size_t IPConsensus::needed() const
{
    return std::ranges::min(tallies | std::views::transform(&Tally::needed));
}
