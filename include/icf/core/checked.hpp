// Inter-Cluster Fabric - checked arithmetic helpers.
//
// Untrusted sizes arriving from the wire or from disk are validated with these helpers
// before any allocation or indexing happens.
#pragma once

#include <cstddef>
#include <cstdint>

namespace icf::checked {

[[nodiscard]] bool add_u64(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept;
[[nodiscard]] bool sub_u64(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept;
[[nodiscard]] bool mul_u64(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept;
[[nodiscard]] bool add_size(std::size_t a, std::size_t b, std::size_t& out) noexcept;
[[nodiscard]] bool mul_size(std::size_t a, std::size_t b, std::size_t& out) noexcept;
[[nodiscard]] bool to_u32(std::uint64_t value, std::uint32_t& out) noexcept;
[[nodiscard]] bool to_size(std::uint64_t value, std::size_t& out) noexcept;
[[nodiscard]] bool to_u16(std::uint64_t value, std::uint16_t& out) noexcept;

}  // namespace icf::checked
