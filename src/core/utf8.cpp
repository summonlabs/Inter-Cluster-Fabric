#include "icf/core/utf8.hpp"

#include <cstdint>

namespace icf {

bool is_valid_utf8(std::string_view text) noexcept {
  std::size_t i = 0;
  const std::size_t size = text.size();
  while (i < size) {
    const auto c0 = static_cast<std::uint8_t>(text[i]);
    std::size_t extra = 0;
    std::uint32_t code_point = 0;
    std::uint32_t minimum = 0;

    if (c0 < 0x80u) {
      i += 1;
      continue;
    }
    if ((c0 & 0xE0u) == 0xC0u) {
      extra = 1;
      code_point = c0 & 0x1Fu;
      minimum = 0x80u;
    } else if ((c0 & 0xF0u) == 0xE0u) {
      extra = 2;
      code_point = c0 & 0x0Fu;
      minimum = 0x800u;
    } else if ((c0 & 0xF8u) == 0xF0u) {
      extra = 3;
      code_point = c0 & 0x07u;
      minimum = 0x10000u;
    } else {
      return false;  // continuation byte or 5/6-byte form
    }

    if (i + extra >= size) {
      return false;  // truncated sequence
    }
    for (std::size_t k = 1; k <= extra; ++k) {
      const auto ck = static_cast<std::uint8_t>(text[i + k]);
      if ((ck & 0xC0u) != 0x80u) {
        return false;
      }
      code_point = (code_point << 6) | (ck & 0x3Fu);
    }
    if (code_point < minimum) {
      return false;  // overlong encoding
    }
    if (code_point > 0x10FFFFu) {
      return false;
    }
    if (code_point >= 0xD800u && code_point <= 0xDFFFu) {
      return false;  // surrogate half
    }
    i += extra + 1;
  }
  return true;
}

std::size_t utf8_prefix_length(std::string_view text, std::size_t max_bytes) noexcept {
  if (text.size() <= max_bytes) {
    return text.size();
  }
  std::size_t end = max_bytes;
  // Walk back over continuation bytes so the prefix ends on a code point boundary.
  while (end > 0 && (static_cast<std::uint8_t>(text[end]) & 0xC0u) == 0x80u) {
    --end;
  }
  return end;
}

}  // namespace icf
