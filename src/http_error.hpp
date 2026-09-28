#pragma once

#include <string>
#include <string_view>
#include <system_error>

#include <magic_enum/magic_enum.hpp>

enum class HTTPError
{
    UnsupportedScheme,
    UnexpectedStatus,
};

namespace std
{
  template <> struct is_error_code_enum<HTTPError> : true_type
  {
  };
}

namespace detail
{
    class HTTPError_category : public std::error_category
    {
    public:
        virtual const char *name() const noexcept override final { return "HTTPError"; }
        virtual std::string message(int c) const override final
        {
            using namespace std::string_view_literals;
            return std::string(magic_enum::enum_cast<HTTPError>(c).
                               transform(&magic_enum::enum_name<HTTPError>).
                               value_or("Unknown HTTPError"sv));
        }

        virtual std::error_condition default_error_condition(int c) const noexcept override final
        {
            return std::error_condition(c, *this);
        }
    };
}

const detail::HTTPError_category& HTTPError_category();
std::error_code make_error_code(HTTPError e);
