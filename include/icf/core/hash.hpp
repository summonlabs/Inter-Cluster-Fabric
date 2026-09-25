// Inter-Cluster Fabric - integrity and identity digests.
//
// CRC32C guards every persisted record and wire frame against accidental corruption.
// SHA-256 is used for content digests that participate in authorization decisions, so it
// must be collision resistant, not merely a checksum.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "icf/core/status.hpp"

namespace icf {

class Digest {
 public:
  static constexpr std::size_t kSize = 32;

  Digest() = default;

  [[nodiscard]] static Digest from_bytes(std::span<const std::byte> bytes);
  [[nodiscard]] static Result<Digest> parse_hex(std::string_view text);

  [[nodiscard]] const std::array<std::byte, kSize>& bytes() const noexcept { return bytes_; }
  [[nodiscard]] bool is_zero() const noexcept;
  [[nodiscard]] std::string hex() const;

  friend bool operator==(const Digest&, const Digest&) noexcept = default;
  friend auto operator<=>(const Digest&, const Digest&) noexcept = default;

 private:
  std::array<std::byte, kSize> bytes_{};
};

[[nodiscard]] std::uint32_t crc32c(std::span<const std::byte> data) noexcept;
[[nodiscard]] std::uint32_t crc32c(std::string_view text) noexcept;
[[nodiscard]] std::uint32_t crc32c_extend(std::uint32_t seed, std::span<const std::byte> data) noexcept;

class Sha256 {
 public:
  Sha256();

  void update(std::span<const std::byte> data);
  void update(std::string_view text);
  [[nodiscard]] Digest digest() const;
  void reset();

  [[nodiscard]] static Digest hash(std::span<const std::byte> data);
  [[nodiscard]] static Digest hash(std::string_view text);

 private:
  void compress(const std::byte* block);

  std::array<std::uint32_t, 8> state_{};
  std::array<std::byte, 64> buffer_{};
  std::size_t buffer_length_ = 0;
  std::uint64_t total_length_ = 0;
};

[[nodiscard]] Digest hmac_sha256(std::span<const std::byte> key, std::span<const std::byte> message);
[[nodiscard]] Digest hmac_sha256(std::string_view key, std::span<const std::byte> message);
// Comparison that does not short-circuit on the first differing byte.
[[nodiscard]] bool constant_time_equal(std::span<const std::byte> a, std::span<const std::byte> b) noexcept;

[[nodiscard]] std::string hex_encode(std::span<const std::byte> data);
[[nodiscard]] Result<std::vector<std::byte>> hex_decode(std::string_view text);

}  // namespace icf
