#pragma once
#include <format>
#include <utility>
#include <iostream>
#include <functional>
#include <systemd/sd-journal.h>

namespace fip
{

    class logger {
    public:
        logger(bool is_testing) : is_verbose(false), is_testing(is_testing) {};
        void set_verbose(bool verbose) { is_verbose = verbose; };

        template <typename Format, typename... Params>
        constexpr void perror(Format&& format, Params&&... params) const {
            auto msg = std::vformat(std::forward<Format>(format), std::make_format_args(params...));
            if (!is_testing) {
                sd_journal_perror(msg.c_str());
            }

            if (is_verbose) {
                perror(msg.c_str());
            }

            if (hook_perror) {
                hook_perror(msg);
            }
        }

        template <typename Message>
        constexpr void perror(Message&& msg) const {
            if (!is_testing) {
                sd_journal_perror(msg);
            }

            if (is_verbose) {
                perror(msg);
            }

            if (hook_perror) {
                hook_perror(std::forward<Message>(msg));
            }
        }

        template <typename Format, typename... Params>
        constexpr void log(int priority, Format&& format, Params&&... params) const {
            auto msg = std::vformat(std::forward<Format>(format), std::make_format_args(params...));
            if (!is_testing) {
                sd_journal_print(priority, msg.c_str());
            }

            if (is_verbose) {
                std::cerr << msg << "\n";
            }

            if (hook_print) {
                hook_print(msg);
            }
        };

        template <typename Message>
        constexpr void log(int priority, Message&& msg) const {
            if (!is_testing) {
                sd_journal_print(priority, msg);
            }

            if (is_verbose) {
                std::cerr << msg << "\n";
            }

            if (hook_print) {
                hook_print(std::forward<Message>(msg));
            }
        };

        template <typename... Params>
        void info(Params&&... params) const {
            return log(LOG_INFO, std::forward<Params>(params)...);
        }

        template <typename... Params>
        void debug(Params&&... params) const {
            return log(LOG_DEBUG, std::forward<Params>(params)...);
        }

        template <typename... Params>
        void warning(Params&&... params) const {
            return log(LOG_WARNING, std::forward<Params>(params)...);
        }

        template <typename... Params>
        void error(Params&&... params) const {
            return log(LOG_ERR, std::forward<Params>(params)...);
        }

        template <typename... Params>
        void notice(Params&&... params) const {
            return log(LOG_NOTICE, std::forward<Params>(params)...);
        }

        std::function<void (const std::string_view&)> hook_print;
        std::function<void (const std::string_view&)> hook_perror;

    private:
        bool is_verbose;
        bool is_testing;
    };
}
