#pragma once

#include "error_category.hpp"

enum class HTTPError
{
    UnsupportedScheme,
    UnexpectedStatus,
};

namespace std
{
  template <> struct is_error_code_enum<HTTPError> : fip::fip_error_code
  {
  };
}
