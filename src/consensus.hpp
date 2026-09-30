#pragma once

#include <array>
#include <cstddef>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>

#include "address_family.hpp"

// How far a vote can be trusted, weakest first: anything on the path could have sent it; the
// provider's authoritative nameserver sent it (AA set); or HTTPS proved who sent it.
enum class Trust {
    Unverified,
    Authoritative,
    Authenticated,
};

class IPConsensus
{
public:
    struct Winner {
        std::string address;
        std::size_t votes;
        std::size_t answers;

        bool operator==(const Winner&) const = default;
    };

    // The winner needs at least one vote at winner_needs; Trust::Unverified asks for nothing more.
    IPConsensus(fip::AddressFamily requested, Trust winner_needs) : requested(requested), winner_needs(winner_needs) { }

    bool record(std::string_view text, Trust trust);

    std::optional<Winner> winner() const;

    std::optional<std::size_t> needed(fip::AddressFamily family) const;

    // Whether the family's leader still lacks a vote at winner_needs, so one must be asked.
    bool needs_trusted(fip::AddressFamily family) const;

    std::size_t answers() const;

private:
    struct Tally {
        std::map<std::string, std::size_t> votes;
        std::map<std::string, Trust> strongest;
        std::size_t total = 0;

        std::map<std::string, std::size_t>::const_iterator leader() const;
        std::size_t leader_votes() const;
        bool leader_trusted(Trust needs) const;
        std::optional<Winner> winner(Trust needs) const;
        std::size_t needed(Trust needs) const;
    };

    std::optional<std::reference_wrapper<Tally>> tally_for(fip::AddressFamily family);
    std::optional<std::reference_wrapper<const Tally>> tally_for(fip::AddressFamily family) const;
    std::optional<std::reference_wrapper<const Tally>> contender(fip::AddressFamily family) const;

    fip::AddressFamily requested;
    Trust winner_needs;
    std::array<Tally, 2> tallies;
};
