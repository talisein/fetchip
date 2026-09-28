#include "http_error.hpp"

const detail::HTTPError_category& HTTPError_category()
{
  static detail::HTTPError_category c;
  return c;
}

std::error_code make_error_code(HTTPError e)
{
    return {magic_enum::enum_integer(e), HTTPError_category()};
}
