#pragma once

#include <string>
#include <string_view>
#include <system_error>

#include <magic_enum/magic_enum.hpp>

enum class FetchError
{
    UnknownServiceType,
};

namespace std
{
  template <> struct is_error_code_enum<FetchError> : true_type
  {
  };
}

namespace detail
{
    class FetchError_category : public std::error_category
    {
    public:
        virtual const char *name() const noexcept override final { return "FetchError"; }
        virtual std::string message(int c) const override final
        {
            using namespace std::string_view_literals;
            return std::string(magic_enum::enum_cast<FetchError>(c).
                               transform(&magic_enum::enum_name<FetchError>).
                               value_or("Unknown FetchError"sv));
        }

        virtual std::error_condition default_error_condition(int c) const noexcept override final
        {
            return std::error_condition(c, *this);
        }
    };
}

const detail::FetchError_category& FetchError_category();
std::error_code make_error_code(FetchError e);
