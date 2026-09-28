#pragma once

#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <string_view>

// Tallies the addresses services report. An address wins once at least two services report it and it holds a strict majority of the answers.
class IPConsensus
{
public:
    // Counts one answer, or returns false if text is not an IP address.
    bool record(std::string_view text);

    std::optional<std::string> winner() const;

    // How many more answers, all agreeing with the leader, would make it win.
    std::size_t needed() const;

    std::size_t answers() const { return total; }

    std::size_t votes_for(const std::string& address) const;

private:
    std::map<std::string, std::size_t>::const_iterator leader() const;
    std::size_t leader_votes() const;

    std::map<std::string, std::size_t> votes;
    std::size_t total = 0;
};
