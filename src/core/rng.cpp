#include "icf/core/rng.hpp"

#include <chrono>
#include <cstdio>
#include <random>
#include <thread>

namespace icf {

std::uint64_t Rng::splitmix64(std::uint64_t& state) noexcept {
  state += 0x9E3779B97F4A7C15ull;
  std::uint64_t z = state;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

std::uint64_t Rng::rotl(std::uint64_t value, int shift) noexcept {
  return (value << shift) | (value >> (64 - shift));
}

Rng::Rng(std::uint64_t seed) noexcept : seed_(seed) {
  std::uint64_t state = seed;
  for (std::size_t i = 0; i < state_.size(); ++i) {
    state_[i] = splitmix64(state);
  }
}

std::uint64_t Rng::next_u64() noexcept {
  const std::uint64_t result = rotl(state_[1] * 5ull, 7) * 9ull;
  const std::uint64_t t = state_[1] << 17;

  state_[2] ^= state_[0];
  state_[3] ^= state_[1];
  state_[1] ^= state_[2];
  state_[0] ^= state_[3];
  state_[2] ^= t;
  state_[3] = rotl(state_[3], 45);
  return result;
}

std::uint32_t Rng::next_u32() noexcept { return static_cast<std::uint32_t>(next_u64() >> 32); }

std::uint64_t Rng::below(std::uint64_t bound) noexcept {
  if (bound <= 1) {
    return 0;
  }
  const std::uint64_t threshold = (0ull - bound) % bound;  // rejection sampling removes bias
  for (;;) {
    const std::uint64_t value = next_u64();
    if (value >= threshold) {
      return value % bound;
    }
  }
}

std::uint64_t Rng::range(std::uint64_t low, std::uint64_t high) noexcept {
  if (high <= low) {
    return low;
  }
  return low + below(high - low + 1);
}

void Rng::fill(std::span<std::byte> out) noexcept {
  std::size_t offset = 0;
  while (offset < out.size()) {
    std::uint64_t value = next_u64();
    for (int i = 0; i < 8 && offset < out.size(); ++i) {
      out[offset] = static_cast<std::byte>(value & 0xFFu);
      value >>= 8;
      ++offset;
    }
  }
}

std::string Rng::state_string() const {
  static constexpr char kHexDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(4 * 16);
  for (const std::uint64_t word : state_) {
    for (int shift = 60; shift >= 0; shift -= 4) {
      out.push_back(kHexDigits[(word >> shift) & 0xFu]);
    }
  }
  return out;
}

std::uint64_t entropy_seed() noexcept {
  std::random_device device;
  std::uint64_t seed = (static_cast<std::uint64_t>(device()) << 32) ^ static_cast<std::uint64_t>(device());
  seed ^= static_cast<std::uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  seed ^= static_cast<std::uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
  return seed;
}

}  // namespace icf
