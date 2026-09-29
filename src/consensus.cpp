#include <algorithm>
#include <ranges>

#include "consensus.hpp"
#include "net.hpp"

namespace {
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

bool IPConsensus::record(std::string_view text)
{
    boost::system::error_code ec;
    auto address = asio::ip::make_address(text, ec);
    if (ec != boost::system::error_code {}) {
        return false;
    }
    auto tally = tally_for(address.is_v6() ? fip::AddressFamily::V6 : fip::AddressFamily::V4);
    if (!tally) {
        return false;
    }
    // Canonical text, so different spellings of one IPv6 address agree.
    ++tally->get().votes[address.to_string()];
    ++tally->get().total;
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

std::optional<IPConsensus::Winner> IPConsensus::Tally::winner() const
{
    auto it = leader();
    if (it == votes.end() || it->second < 2 || 2 * it->second <= total) {
        return std::nullopt;
    }
    return Winner {it->first, it->second, total};
}

std::size_t IPConsensus::Tally::needed() const
{
    // k agreeing answers win when leader + k >= 2 and 2 * (leader + k) > total + k.
    const auto leader = leader_votes();
    const std::size_t for_majority = total + 1 > 2 * leader ? total + 1 - 2 * leader : 0;
    const std::size_t for_pair = leader < 2 ? 2 - leader : 0;
    return std::max(for_majority, for_pair);
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
        if (auto winner = contender(family).and_then(&Tally::winner)) {
            return winner;
        }
    }
    return std::nullopt;
}

std::optional<std::size_t> IPConsensus::needed(fip::AddressFamily family) const
{
    return contender(family).transform(&Tally::needed);
}
