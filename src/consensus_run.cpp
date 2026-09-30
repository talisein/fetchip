#include <algorithm>
#include <functional>
#include <ranges>
#include <utility>

#include <magic_enum/magic_enum.hpp>
#include "consensus_run.hpp"
#include "fetch_error.hpp"

void log_exception(fip::context& ctx, std::string_view who, std::exception_ptr e)
{
    try { std::rethrow_exception(e); }
    catch (const std::system_error& ex) {
        ctx.log.error("{} failed: {} ({}:{})", who, ex.what(), ex.code().category().name(), ex.code().value());
    }
    catch (const boost::system::system_error& ex) {
        ctx.log.error("{} failed: {} ({}:{})", who, ex.what(), ex.code().category().name(), ex.code().value());
    }
    catch (const std::exception& ex) {
        ctx.log.error("{} failed: {}", who, ex.what());
    }
    catch (...) {
        ctx.log.error("{} failed with an unknown exception", who);
    }
}

namespace {
    auto can_vote(fip::AddressFamily family, Trust at_least)
    {
        return [family, at_least](const Service& service) {
            return serves_family(service, family) && trust_of(service) >= at_least;
        };
    }
}

// The winner needs a vote from the most trusted kind of service the run can ask.
ConsensusRun::ConsensusRun(fip::context& ctx, std::vector<Service> candidates, PublicIpQuery query) :
    ctx(ctx),
    candidates(std::move(candidates)),
    query(std::move(query)),
    winner_needs(std::ranges::fold_left(this->candidates | std::views::transform(trust_of), Trust::Unverified, std::ranges::max)),
    consensus(ctx.requested_family, winner_needs)
{ }

std::expected<std::string, std::error_code> ConsensusRun::run()
{
    top_up();
    ctx.io_context.run();
    if (!public_ip) {
        return std::unexpected(make_error_code(FetchError::NoConsensus));
    }
    return std::move(*public_ip);
}

std::size_t ConsensusRun::in_flight(fip::AddressFamily family, Trust at_least) const
{
    const auto count = std::ranges::count_if(queries, [voter = can_vote(family, at_least)](const Query& query) {
        return query.running && voter(query.service);
    });
    return static_cast<std::size_t>(count);
}

std::size_t ConsensusRun::left(fip::AddressFamily family, Trust at_least) const
{
    const auto count = std::ranges::count_if(candidates, can_vote(family, at_least));
    return static_cast<std::size_t>(count);
}

// Stragglers can no longer change the outcome.
void ConsensusRun::settle()
{
    settled = true;
    for (auto& query : queries) {
        if (query.running) {
            query.cancel.emit(asio::cancellation_type::terminal);
        }
    }
}

void ConsensusRun::top_up()
{
    // Only services that can answer in a family can vote in it, so a family stays open while
    // enough of them are in flight or left. Every open family is kept topped up, so whichever
    // wins first is printed. A family whose leader still lacks a trusted vote also needs a
    // trusted service, and one is drawn first so it runs alongside the rest.
    bool open = false;
    for (const auto family : {fip::AddressFamily::V4, fip::AddressFamily::V6}) {
        const auto needed = consensus.needed(family);
        if (!needed || in_flight(family, Trust::Unverified) + left(family, Trust::Unverified) < *needed) {
            continue;
        }
        const bool needs_trusted = consensus.needs_trusted(family);
        if (needs_trusted && in_flight(family, winner_needs) + left(family, winner_needs) == 0) {
            ctx.log.debug("No {} service left to confirm a {} answer", magic_enum::enum_name(winner_needs), magic_enum::enum_name(family));
            continue;
        }
        open = true;
        if (needs_trusted && in_flight(family, winner_needs) == 0) {
            draw(family, winner_needs);
        }
        while (in_flight(family, Trust::Unverified) < *needed) {
            if (!draw(family, Trust::Unverified)) {
                break;
            }
        }
    }
    if (!open) {
        const auto running = std::ranges::count(queries, true, &Query::running);
        ctx.log.error("No consensus from {} answers, {} in flight and {} services left", consensus.answers(), running, candidates.size());
        settle();
    }
}

// Candidates are shuffled once and drawn from the back, so each is asked at most once.
bool ConsensusRun::draw(fip::AddressFamily family, Trust at_least)
{
    const auto next = std::ranges::find_last_if(candidates, can_vote(family, at_least)).begin();
    if (next == candidates.end()) {
        return false;
    }
    const auto service = *next;
    candidates.erase(next);
    launch(service);
    return true;
}

void ConsensusRun::launch(const Service& service)
{
    auto& launched = queries.emplace_back(service);
    asio::co_spawn(ctx.io_context, query(service),
                   asio::bind_cancellation_slot(launched.cancel.slot(),
                   [this, &launched](std::exception_ptr e, std::expected<std::string, std::error_code> result) {
                       on_done(launched, e, std::move(result));
                   }));
}

void ConsensusRun::on_done(Query& done, std::exception_ptr e, std::expected<std::string, std::error_code> result)
{
    done.running = false;
    // A cancelled query unwinds by throwing operation_aborted from its next co_await.
    if (settled) {
        return;
    }
    // One failed query is one lost vote, never the whole run.
    if (e) {
        log_exception(ctx, done.service.address, e);
        top_up();
        return;
    }
    if (result && !consensus.record(*result, trust_of(done.service))) {
        ctx.log.debug("{} did not answer with an address: {}", done.service.address, *result);
    }
    if (auto winner = consensus.winner()) {
        ctx.log.notice("{} of {} answers agreed on {}", winner->votes, winner->answers, winner->address);
        public_ip = std::move(winner->address);
        settle();
        return;
    }
    top_up();
}
