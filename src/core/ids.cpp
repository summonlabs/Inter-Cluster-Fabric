#include "icf/core/ids.hpp"

#include "icf/core/rng.hpp"

namespace icf {
namespace {

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

}  // namespace

Uuid Uuid::random(Rng& rng) {
  std::array<std::byte, kSize> bytes{};
  rng.fill(bytes);
  // RFC 4122 version 4 layout: the identifiers are random, not derived from any secret.
  bytes[6] = static_cast<std::byte>((std::to_integer<std::uint8_t>(bytes[6]) & 0x0Fu) | 0x40u);
  bytes[8] = static_cast<std::byte>((std::to_integer<std::uint8_t>(bytes[8]) & 0x3Fu) | 0x80u);
  Uuid result;
  result.bytes_ = bytes;
  return result;
}

Uuid Uuid::from_bytes(std::span<const std::byte> bytes) {
  Uuid result;
  const std::size_t count = bytes.size() < kSize ? bytes.size() : kSize;
  for (std::size_t i = 0; i < count; ++i) {
    result.bytes_[i] = bytes[i];
  }
  return result;
}

Uuid Uuid::from_random_bytes(std::span<const std::byte> bytes) { return from_bytes(bytes); }

Result<Uuid> Uuid::parse(std::string_view text) {
  std::array<std::byte, kSize> bytes{};
  std::size_t written = 0;
  int high = -1;
  for (const char c : text) {
    if (c == '-') {
      continue;
    }
    const int value = hex_value(c);
    if (value < 0) {
      return invalid("uuid contains a non-hex character");
    }
    if (high < 0) {
      high = value;
      continue;
    }
    if (written >= kSize) {
      return invalid("uuid is longer than 32 hex characters");
    }
    bytes[written] = static_cast<std::byte>((high << 4) | value);
    ++written;
    high = -1;
  }
  if (high >= 0 || written != kSize) {
    return invalid("uuid must contain exactly 32 hex characters");
  }
  Uuid result;
  result.bytes_ = bytes;
  return result;
}

bool Uuid::is_nil() const noexcept {
  for (const std::byte byte : bytes_) {
    if (byte != std::byte{0}) {
      return false;
    }
  }
  return true;
}

std::string Uuid::hex() const {
  static constexpr char kHexDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(kSize * 2);
  for (const std::byte byte : bytes_) {
    const auto value = std::to_integer<std::uint8_t>(byte);
    out.push_back(kHexDigits[value >> 4]);
    out.push_back(kHexDigits[value & 0x0Fu]);
  }
  return out;
}

std::string Uuid::to_string() const {
  const std::string raw = hex();
  std::string out;
  out.reserve(36);
  for (std::size_t i = 0; i < raw.size(); ++i) {
    if (i == 8 || i == 12 || i == 16 || i == 20) {
      out.push_back('-');
    }
    out.push_back(raw[i]);
  }
  return out;
}

}  // namespace icf
