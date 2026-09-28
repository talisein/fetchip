#include "fetch_error.hpp"

const detail::FetchError_category& FetchError_category()
{
  static detail::FetchError_category c;
  return c;
}

std::error_code make_error_code(FetchError e)
{
    return {magic_enum::enum_integer(e), FetchError_category()};
}
