// Inter-Cluster Fabric - UTF-8 validation.
//
// Identities, scopes, and operator-supplied labels arrive from the wire and from disk.
// Invalid UTF-8 (overlong encodings, surrogates, truncated sequences, code points above
// U+10FFFF) is rejected as INVALID before the text is stored or echoed.
#pragma once

#include <cstddef>
#include <string_view>

namespace icf {

[[nodiscard]] bool is_valid_utf8(std::string_view text) noexcept;
// Returns the largest prefix length <= max_bytes that ends on a code point boundary.
[[nodiscard]] std::size_t utf8_prefix_length(std::string_view text, std::size_t max_bytes) noexcept;

}  // namespace icf
