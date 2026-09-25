// Inter-Cluster Fabric - deterministic seeded randomness.
//
// Tests and property runs are seeded so that a failure can be replayed exactly. Randomness
// never participates in an authorization decision: identifiers and jitter are the only
// consumers.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace icf {

class Rng {
 public:
  explicit Rng(std::uint64_t seed) noexcept;

  [[nodiscard]] std::uint64_t next_u64() noexcept;
  [[nodiscard]] std::uint32_t next_u32() noexcept;
  // Uniform in [0, bound). bound must be non-zero.
  [[nodiscard]] std::uint64_t below(std::uint64_t bound) noexcept;
  // Uniform in [low, high] inclusive. high must be >= low.
  [[nodiscard]] std::uint64_t range(std::uint64_t low, std::uint64_t high) noexcept;
  void fill(std::span<std::byte> out) noexcept;

  [[nodiscard]] std::uint64_t seed() const noexcept { return seed_; }
  [[nodiscard]] std::string state_string() const;

 private:
  static std::uint64_t splitmix64(std::uint64_t& state) noexcept;
  static std::uint64_t rotl(std::uint64_t value, int shift) noexcept;

  std::array<std::uint64_t, 4> state_{};
  std::uint64_t seed_ = 0;
};

// Seed for runs that are not replayed: mixes the process id, a monotonic counter, and the
// system entropy source.
[[nodiscard]] std::uint64_t entropy_seed() noexcept;

}  // namespace icf
