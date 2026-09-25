#include "icf/core/hash.hpp"

#include <array>
#include <cmath>
#include <cstring>
#include <vector>

namespace icf {
namespace {

constexpr std::array<std::uint32_t, 256> make_crc32c_table() {
  std::array<std::uint32_t, 256> table{};
  for (std::uint32_t i = 0; i < 256; ++i) {
    std::uint32_t crc = i;
    for (int bit = 0; bit < 8; ++bit) {
      crc = (crc & 1u) != 0u ? ((crc >> 1) ^ 0x82F63B78u) : (crc >> 1);
    }
    table[i] = crc;
  }
  return table;
}

constexpr auto kCrc32cTable = make_crc32c_table();

std::array<std::uint32_t, 64> make_sha256_k() {
  std::array<std::uint32_t, 64> k{};
  const std::array<std::uint32_t, 8> primes{2, 3, 5, 7, 11, 13, 17, 19};
  std::size_t index = 0;
  for (std::uint32_t candidate = 2; index < 64; ++candidate) {
    bool prime = true;
    for (const std::uint32_t p : primes) {
      if (p * p > candidate) {
        break;
      }
      if (candidate % p == 0) {
        prime = false;
        break;
      }
    }
    if (!prime) {
      continue;
    }
    // Fractional part of the cube root of the first 64 primes.
    const double root = std::cbrt(static_cast<double>(candidate));
    const double fraction = root - static_cast<double>(static_cast<std::uint64_t>(root));
    k[index] = static_cast<std::uint32_t>(fraction * 4294967296.0);
    ++index;
  }
  return k;
}

}  // namespace

std::uint32_t crc32c_extend(std::uint32_t seed, std::span<const std::byte> data) noexcept {
  std::uint32_t crc = ~seed;
  for (const std::byte byte : data) {
    const auto index = static_cast<std::uint8_t>(crc ^ static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(byte)));
    crc = kCrc32cTable[index] ^ (crc >> 8);
  }
  return ~crc;
}

std::uint32_t crc32c(std::span<const std::byte> data) noexcept { return crc32c_extend(0u, data); }

std::uint32_t crc32c(std::string_view text) noexcept {
  return crc32c(std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

Digest Digest::from_bytes(std::span<const std::byte> bytes) {
  Digest digest;
  const std::size_t count = bytes.size() < kSize ? bytes.size() : kSize;
  for (std::size_t i = 0; i < count; ++i) {
    digest.bytes_[i] = bytes[i];
  }
  return digest;
}

Result<Digest> Digest::parse_hex(std::string_view text) {
  if (text.size() != kSize * 2) {
    return invalid("digest must be 64 hex characters");
  }
  Result<std::vector<std::byte>> raw = hex_decode(text);
  if (!raw) {
    return raw.status();
  }
  return Digest::from_bytes(raw.value());
}

bool Digest::is_zero() const noexcept {
  for (const std::byte byte : bytes_) {
    if (byte != std::byte{0}) {
      return false;
    }
  }
  return true;
}

std::string Digest::hex() const { return hex_encode(bytes_); }

Sha256::Sha256() { reset(); }

void Sha256::reset() {
  state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
  buffer_.fill(std::byte{0});
  buffer_length_ = 0;
  total_length_ = 0;
}

void Sha256::compress(const std::byte* block) {
  static const std::array<std::uint32_t, 64> k = make_sha256_k();

  std::array<std::uint32_t, 64> w{};
  for (std::size_t i = 0; i < 16; ++i) {
    const auto b0 = static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(block[i * 4 + 0]));
    const auto b1 = static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(block[i * 4 + 1]));
    const auto b2 = static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(block[i * 4 + 2]));
    const auto b3 = static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(block[i * 4 + 3]));
    w[i] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t s0 = ((w[i - 15] >> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >> 3);
    const std::uint32_t s1 = ((w[i - 2] >> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t s1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
    const std::uint32_t ch = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + ch + k[i] + w[i];
    const std::uint32_t s0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(std::span<const std::byte> data) {
  total_length_ += static_cast<std::uint64_t>(data.size());
  std::size_t offset = 0;
  while (offset < data.size()) {
    const std::size_t free_space = 64 - buffer_length_;
    std::size_t take = data.size() - offset;
    if (take > free_space) {
      take = free_space;
    }
    std::memcpy(buffer_.data() + buffer_length_, data.data() + offset, take);
    buffer_length_ += take;
    offset += take;
    if (buffer_length_ == 64) {
      compress(buffer_.data());
      buffer_length_ = 0;
    }
  }
}

void Sha256::update(std::string_view text) {
  update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

Digest Sha256::digest() const {
  Sha256 copy = *this;
  const std::uint64_t bit_length = copy.total_length_ * 8;

  // Append 0x80 and zeros so the message length lands at 56 mod 64, then the 64-bit
  // big-endian bit length. The padding update always stops exactly at offset 56.
  std::array<std::byte, 64> padding{};
  padding[0] = std::byte{0x80};
  const std::size_t pad_length = copy.buffer_length_ < 56 ? (56 - copy.buffer_length_) : (120 - copy.buffer_length_);
  copy.update(std::span<const std::byte>(padding.data(), pad_length));

  for (std::size_t i = 0; i < 8; ++i) {
    copy.buffer_[56 + i] = static_cast<std::byte>((bit_length >> (56 - i * 8)) & 0xFFu);
  }
  copy.compress(copy.buffer_.data());
  copy.buffer_length_ = 0;

  std::array<std::byte, Digest::kSize> out{};
  for (std::size_t i = 0; i < 8; ++i) {
    out[i * 4 + 0] = static_cast<std::byte>((copy.state_[i] >> 24) & 0xFFu);
    out[i * 4 + 1] = static_cast<std::byte>((copy.state_[i] >> 16) & 0xFFu);
    out[i * 4 + 2] = static_cast<std::byte>((copy.state_[i] >> 8) & 0xFFu);
    out[i * 4 + 3] = static_cast<std::byte>(copy.state_[i] & 0xFFu);
  }
  return Digest::from_bytes(out);
}

Digest Sha256::hash(std::span<const std::byte> data) {
  Sha256 hasher;
  hasher.update(data);
  return hasher.digest();
}

Digest Sha256::hash(std::string_view text) {
  Sha256 hasher;
  hasher.update(text);
  return hasher.digest();
}

Digest hmac_sha256(std::span<const std::byte> key, std::span<const std::byte> message) {
  std::array<std::byte, 64> block_key{};
  if (key.size() > 64) {
    const Digest hashed = Sha256::hash(key);
    std::memcpy(block_key.data(), hashed.bytes().data(), Digest::kSize);
  } else {
    std::memcpy(block_key.data(), key.data(), key.size());
  }

  std::array<std::byte, 64> inner_pad{};
  std::array<std::byte, 64> outer_pad{};
  for (std::size_t i = 0; i < 64; ++i) {
    inner_pad[i] = static_cast<std::byte>(std::to_integer<std::uint8_t>(block_key[i]) ^ 0x36u);
    outer_pad[i] = static_cast<std::byte>(std::to_integer<std::uint8_t>(block_key[i]) ^ 0x5cu);
  }

  Sha256 inner;
  inner.update(inner_pad);
  inner.update(message);
  const Digest inner_digest = inner.digest();

  Sha256 outer;
  outer.update(outer_pad);
  outer.update(inner_digest.bytes());
  return outer.digest();
}

Digest hmac_sha256(std::string_view key, std::span<const std::byte> message) {
  return hmac_sha256(std::span<const std::byte>(reinterpret_cast<const std::byte*>(key.data()), key.size()), message);
}

bool constant_time_equal(std::span<const std::byte> a, std::span<const std::byte> b) noexcept {
  if (a.size() != b.size()) {
    return false;
  }
  std::uint8_t difference = 0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    difference = static_cast<std::uint8_t>(difference | (std::to_integer<std::uint8_t>(a[i]) ^ std::to_integer<std::uint8_t>(b[i])));
  }
  return difference == 0;
}

std::string hex_encode(std::span<const std::byte> data) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (const std::byte byte : data) {
    const auto value = std::to_integer<std::uint8_t>(byte);
    out.push_back(kHex[value >> 4]);
    out.push_back(kHex[value & 0x0Fu]);
  }
  return out;
}

Result<std::vector<std::byte>> hex_decode(std::string_view text) {
  if (text.size() % 2 != 0) {
    return invalid("hex string must have an even length");
  }
  auto nibble = [](char c) -> int {
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
  };
  std::vector<std::byte> out;
  out.reserve(text.size() / 2);
  for (std::size_t i = 0; i < text.size(); i += 2) {
    const int high = nibble(text[i]);
    const int low = nibble(text[i + 1]);
    if (high < 0 || low < 0) {
      return invalid("hex string contains a non-hex character");
    }
    out.push_back(static_cast<std::byte>((high << 4) | low));
  }
  return out;
}

}  // namespace icf
