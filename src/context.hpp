#pragma once
#include "log.hpp"
#include <pcg_random.hpp>
#include <random>

#include <asio/ts/io_context.hpp>

namespace fip
{

    struct context {
    public:
        context(pcg32::state_type seed, bool is_testing = false) :
            rng(seed),
            is_testing(is_testing),
            log(is_testing)
        { }

        context(bool is_testing = false) :
            rng(pcg_extras::seed_seq_from<std::random_device>()),
            is_testing(is_testing),
            log(is_testing)
        { }

        pcg32 rng;
        bool is_testing;
        logger log;

        enum class RequestedFamily {
            IP4,
            IP6
        } requested_family;

        asio::io_context io_context;
    };
}
