#pragma once

#include <concepts>
#include <format>
#include <string>
#include <system_error>
#include <type_traits>

#include <magic_enum/magic_enum.hpp>

namespace fip
{
    struct fip_error_code : std::true_type
    {
    };

    template <typename E>
    concept fip_error = std::is_enum_v<E> &&
        std::derived_from<std::is_error_code_enum<E>, fip_error_code>;

    template <fip_error E>
    class fip_category final : public std::error_category
    {
    public:
        const char *name() const noexcept override { return magic_enum::enum_type_name<E>().data(); }
        std::string message(int c) const override
        {
            return magic_enum::enum_cast<E>(c).
                transform([](E e) { return std::string(magic_enum::enum_name(e)); }).
                value_or(std::format("Unknown {}", name()));
        }
    };

    template <fip_error E>
    const std::error_category& error_category() noexcept
    {
        static const fip_category<E> c;
        return c;
    }
}

template <fip::fip_error E>
std::error_code make_error_code(E e) noexcept
{
    return {magic_enum::enum_integer(e), fip::error_category<E>()};
}
