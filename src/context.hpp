#pragma once
#include "log.hpp"
#include <pcg_random.hpp>
#include <random>

#include "net.hpp"

namespace fip
{
    enum class AddressFamily {
        Any,
        V4,
        V6
    };

    struct context {
    public:
        context(pcg32::state_type seed, bool is_testing = false) :
            rng(seed),
            is_testing(is_testing),
            log(is_testing),
            ssl_context(make_ssl_context())
        { }

        context(bool is_testing = false) :
            rng(pcg_extras::seed_seq_from<std::random_device>()),
            is_testing(is_testing),
            log(is_testing),
            ssl_context(make_ssl_context())
        { }

        pcg32 rng;
        bool is_testing;
        logger log;

        AddressFamily requested_family = AddressFamily::Any;

        asio::io_context io_context;
        asio::ssl::context ssl_context;

    private:
        static asio::ssl::context make_ssl_context()
        {
            asio::ssl::context c {asio::ssl::context::tls_client};
            c.set_default_verify_paths();
            c.set_verify_mode(asio::ssl::verify_peer);
            return c;
        }
    };
}
