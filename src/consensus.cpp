#include <algorithm>
#include <ranges>

#include "consensus.hpp"
#include "net.hpp"

bool IPConsensus::record(std::string_view text)
{
    boost::system::error_code ec;
    auto address = asio::ip::make_address(text, ec);
    if (ec) {
        return false;
    }
    // Canonical text, so different spellings of one IPv6 address agree.
    ++votes[address.to_string()];
    ++total;
    return true;
}

std::map<std::string, std::size_t>::const_iterator IPConsensus::leader() const
{
    return std::ranges::max_element(std::views::values(votes)).base();
}

std::size_t IPConsensus::leader_votes() const
{
    auto it = leader();
    return it == votes.end() ? 0 : it->second;
}

std::size_t IPConsensus::votes_for(const std::string& address) const
{
    auto it = votes.find(address);
    return it == votes.end() ? 0 : it->second;
}

std::optional<std::string> IPConsensus::winner() const
{
    auto it = leader();
    if (it == votes.end() || it->second < 2 || 2 * it->second <= total) {
        return std::nullopt;
    }
    return it->first;
}

std::size_t IPConsensus::needed() const
{
    // k agreeing answers win when leader + k >= 2 and 2 * (leader + k) > total + k.
    const auto leader = leader_votes();
    const std::size_t for_majority = total + 1 > 2 * leader ? total + 1 - 2 * leader : 0;
    const std::size_t for_pair = leader < 2 ? 2 - leader : 0;
    return std::max(for_majority, for_pair);
}
