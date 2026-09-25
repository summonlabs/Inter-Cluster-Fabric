// Inter-Cluster Fabric - bounded byte buffer helpers.
//
// Appending to a byte buffer happens with untrusted lengths, so the checked helpers live next
// to the limits they enforce.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "icf/core/checked.hpp"
#include "icf/core/limits.hpp"
#include "icf/core/status.hpp"

namespace icf {

// Returns an overflow status when a + b would exceed the size type.
[[nodiscard]] inline Result<std::size_t> checked_sum(std::size_t a, std::size_t b) {
  std::size_t out = 0;
  if (!checked::add_size(a, b, out)) {
    return Status::make(Outcome::Overflow, "size computation overflow");
  }
  return out;
}

}  // namespace icf
