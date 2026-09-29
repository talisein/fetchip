#pragma once

#include "error_category.hpp"

enum class FetchError
{
    UnknownServiceType,
    NameResolutionFailed,
};

namespace std
{
  template <> struct is_error_code_enum<FetchError> : fip::fip_error_code
  {
  };
}
