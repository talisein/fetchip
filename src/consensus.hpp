#pragma once

#include <array>
#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <string_view>

class IPConsensus
{
public:
    bool record(std::string_view text);

    std::optional<std::string> winner() const;

    std::size_t needed() const;

    std::size_t answers() const;

    std::size_t votes_for(const std::string& address) const;

private:
    struct Tally {
        std::map<std::string, std::size_t> votes;
        std::size_t total = 0;

        std::map<std::string, std::size_t>::const_iterator leader() const;
        std::size_t leader_votes() const;
        std::optional<std::string> winner() const;
        std::size_t needed() const;
    };

    std::array<Tally, 2> tallies;
};
