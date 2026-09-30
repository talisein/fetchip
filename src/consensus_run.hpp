#pragma once

#include <cstddef>
#include <exception>
#include <expected>
#include <functional>
#include <list>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "consensus.hpp"
#include "context.hpp"
#include "services.hpp"

using PublicIpQuery = std::function<asio::awaitable<std::expected<std::string, std::error_code>>(Service)>;

void log_exception(fip::context& ctx, std::string_view who, std::exception_ptr e);

class ConsensusRun
{
public:
    ConsensusRun(fip::context& ctx, std::vector<Service> candidates, PublicIpQuery query);

    std::expected<std::string, std::error_code> run();

private:
    struct Query {
        Service service;
        asio::cancellation_signal cancel;
        bool running = true;
    };

    void top_up();
    void launch(const Service& service);
    void on_done(Query& query, std::exception_ptr e, std::expected<std::string, std::error_code> result);
    void settle();
    std::size_t in_flight(fip::AddressFamily family) const;
    std::size_t left(fip::AddressFamily family) const;

    fip::context& ctx;
    std::vector<Service> candidates;
    PublicIpQuery query;
    IPConsensus consensus;
    std::list<Query> queries;
    bool settled = false;
    std::optional<std::string> public_ip;
};
