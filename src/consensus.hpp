#pragma once

#include <array>
#include <cstddef>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>

#include "address_family.hpp"

class IPConsensus
{
public:
    struct Winner {
        std::string address;
        std::size_t votes;
        std::size_t answers;

        bool operator==(const Winner&) const = default;
    };

    explicit IPConsensus(fip::AddressFamily requested) : requested(requested) { }

    bool record(std::string_view text);

    std::optional<Winner> winner() const;

    std::optional<std::size_t> needed(fip::AddressFamily family) const;

    std::size_t answers() const;

private:
    struct Tally {
        std::map<std::string, std::size_t> votes;
        std::size_t total = 0;

        std::map<std::string, std::size_t>::const_iterator leader() const;
        std::size_t leader_votes() const;
        std::optional<Winner> winner() const;
        std::size_t needed() const;
    };

    std::optional<std::reference_wrapper<Tally>> tally_for(fip::AddressFamily family);
    std::optional<std::reference_wrapper<const Tally>> tally_for(fip::AddressFamily family) const;
    std::optional<std::reference_wrapper<const Tally>> contender(fip::AddressFamily family) const;

    fip::AddressFamily requested;
    std::array<Tally, 2> tallies;
};
