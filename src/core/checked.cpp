#include "icf/core/checked.hpp"

#include <limits>

namespace icf::checked {

bool add_u64(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
  if (a > std::numeric_limits<std::uint64_t>::max() - b) {
    return false;
  }
  out = a + b;
  return true;
}

bool sub_u64(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
  if (b > a) {
    return false;
  }
  out = a - b;
  return true;
}

bool mul_u64(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
  if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a) {
    return false;
  }
  out = a * b;
  return true;
}

bool add_size(std::size_t a, std::size_t b, std::size_t& out) noexcept {
  if (a > std::numeric_limits<std::size_t>::max() - b) {
    return false;
  }
  out = a + b;
  return true;
}

bool mul_size(std::size_t a, std::size_t b, std::size_t& out) noexcept {
  if (a != 0 && b > std::numeric_limits<std::size_t>::max() / a) {
    return false;
  }
  out = a * b;
  return true;
}

bool to_u32(std::uint64_t value, std::uint32_t& out) noexcept {
  if (value > std::numeric_limits<std::uint32_t>::max()) {
    return false;
  }
  out = static_cast<std::uint32_t>(value);
  return true;
}

bool to_u16(std::uint64_t value, std::uint16_t& out) noexcept {
  if (value > std::numeric_limits<std::uint16_t>::max()) {
    return false;
  }
  out = static_cast<std::uint16_t>(value);
  return true;
}

bool to_size(std::uint64_t value, std::size_t& out) noexcept {
  if (value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    return false;
  }
  out = static_cast<std::size_t>(value);
  return true;
}

}  // namespace icf::checked
