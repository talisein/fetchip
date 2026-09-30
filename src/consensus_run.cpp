#include <algorithm>
#include <functional>
#include <utility>

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

ConsensusRun::ConsensusRun(fip::context& ctx, std::vector<Service> candidates, PublicIpQuery query) :
    ctx(ctx),
    candidates(std::move(candidates)),
    query(std::move(query)),
    consensus(ctx.requested_family)
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

std::size_t ConsensusRun::in_flight(fip::AddressFamily family) const
{
    const auto count = std::ranges::count_if(queries, [family](const Query& query) {
        return query.running && serves_family(query.service, family);
    });
    return static_cast<std::size_t>(count);
}

std::size_t ConsensusRun::left(fip::AddressFamily family) const
{
    const auto count = std::ranges::count_if(candidates, std::bind_back(serves_family, family));
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
    // wins first is printed.
    bool open = false;
    for (const auto family : {fip::AddressFamily::V4, fip::AddressFamily::V6}) {
        const auto needed = consensus.needed(family);
        if (!needed || in_flight(family) + left(family) < *needed) {
            continue;
        }
        open = true;
        while (in_flight(family) < *needed) {
            const auto next = std::ranges::find_last_if(candidates, std::bind_back(serves_family, family)).begin();
            if (next == candidates.end()) {
                break;
            }
            const auto service = *next;
            candidates.erase(next);
            launch(service);
        }
    }
    if (!open) {
        const auto running = std::ranges::count(queries, true, &Query::running);
        ctx.log.error("No consensus from {} answers, {} in flight and {} services left", consensus.answers(), running, candidates.size());
        settle();
    }
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
    if (result && !consensus.record(*result)) {
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
