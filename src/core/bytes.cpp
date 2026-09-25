#include "icf/core/bytes.hpp"

#include <cstring>

#include "icf/core/checked.hpp"
#include "icf/core/limits.hpp"
#include "icf/core/utf8.hpp"

namespace icf {
namespace {

void append_be(std::vector<std::byte>& out, std::uint64_t value, std::size_t width) {
  for (std::size_t i = 0; i < width; ++i) {
    const std::size_t shift = (width - 1 - i) * 8;
    out.push_back(static_cast<std::byte>((value >> shift) & 0xFFu));
  }
}

bool read_be(std::span<const std::byte> data, std::size_t& offset, std::size_t width, std::uint64_t& out) {
  if (width > data.size() - offset) {
    return false;
  }
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < width; ++i) {
    value = (value << 8) | std::to_integer<std::uint8_t>(data[offset + i]);
  }
  offset += width;
  out = value;
  return true;
}

}  // namespace

void ByteWriter::u8(std::uint8_t value) { data_.push_back(static_cast<std::byte>(value)); }

void ByteWriter::u16(std::uint16_t value) { append_be(data_, value, 2); }

void ByteWriter::u32(std::uint32_t value) { append_be(data_, value, 4); }

void ByteWriter::u64(std::uint64_t value) { append_be(data_, value, 8); }

void ByteWriter::i64(std::int64_t value) { append_be(data_, static_cast<std::uint64_t>(value), 8); }

void ByteWriter::boolean(bool value) { u8(value ? 1u : 0u); }

void ByteWriter::raw(std::span<const std::byte> data) { data_.insert(data_.end(), data.begin(), data.end()); }

void ByteWriter::blob(std::string_view text) {
  u32(static_cast<std::uint32_t>(text.size()));
  raw(std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

void ByteWriter::uuid(const Uuid& value) { raw(value.bytes()); }

void ByteWriter::digest(const Digest& value) { raw(value.bytes()); }

bool ByteWriter::count(std::size_t value) {
  std::uint32_t narrowed = 0;
  if (!checked::to_u32(value, narrowed)) {
    return false;
  }
  u32(narrowed);
  return true;
}

Result<std::uint8_t> ByteReader::u8() {
  if (remaining() < 1) {
    return Status::make(Outcome::Incomplete, "truncated frame: uint8");
  }
  return std::to_integer<std::uint8_t>(data_[offset_++]);
}

Result<std::uint16_t> ByteReader::u16() {
  std::uint64_t value = 0;
  if (!read_be(data_, offset_, 2, value)) {
    return Status::make(Outcome::Incomplete, "truncated frame: uint16");
  }
  return static_cast<std::uint16_t>(value);
}

Result<std::uint32_t> ByteReader::u32() {
  std::uint64_t value = 0;
  if (!read_be(data_, offset_, 4, value)) {
    return Status::make(Outcome::Incomplete, "truncated frame: uint32");
  }
  return static_cast<std::uint32_t>(value);
}

Result<std::uint64_t> ByteReader::u64() {
  std::uint64_t value = 0;
  if (!read_be(data_, offset_, 8, value)) {
    return Status::make(Outcome::Incomplete, "truncated frame: uint64");
  }
  return value;
}

Result<std::int64_t> ByteReader::i64() {
  Result<std::uint64_t> value = u64();
  if (!value) {
    return value.status();
  }
  return static_cast<std::int64_t>(value.value());
}

Result<bool> ByteReader::boolean() {
  Result<std::uint8_t> value = u8();
  if (!value) {
    return value.status();
  }
  if (value.value() > 1) {
    return invalid("boolean field must be 0 or 1");
  }
  return value.value() == 1;
}

Result<std::span<const std::byte>> ByteReader::raw(std::size_t count) {
  if (count > remaining()) {
    return Status::make(Outcome::Incomplete, "truncated frame: byte field");
  }
  const std::span<const std::byte> slice = data_.subspan(offset_, count);
  offset_ += count;
  return slice;
}

Result<std::string> ByteReader::blob(std::size_t max_length) {
  Result<std::uint32_t> length = u32();
  if (!length) {
    return length.status();
  }
  if (length.value() > max_length) {
    return invalid("string field exceeds the maximum permitted length");
  }
  Result<std::span<const std::byte>> body = raw(length.value());
  if (!body) {
    return body.status();
  }
  std::string text(reinterpret_cast<const char*>(body.value().data()), body.value().size());
  if (!is_valid_utf8(text)) {
    return invalid("string field is not valid UTF-8");
  }
  return text;
}

Result<Uuid> ByteReader::uuid() {
  Result<std::span<const std::byte>> body = raw(16);
  if (!body) {
    return body.status();
  }
  return Uuid::from_bytes(body.value());
}

Result<Digest> ByteReader::digest() {
  Result<std::span<const std::byte>> body = raw(Digest::kSize);
  if (!body) {
    return body.status();
  }
  return Digest::from_bytes(body.value());
}

Result<std::size_t> ByteReader::count(std::size_t max_count) {
  Result<std::uint32_t> value = u32();
  if (!value) {
    return value.status();
  }
  if (value.value() > max_count) {
    return invalid("collection count exceeds the maximum permitted size");
  }
  return static_cast<std::size_t>(value.value());
}

Status ByteReader::expect_end() const {
  if (!at_end()) {
    return invalid("frame contains trailing bytes beyond the declared schema");
  }
  return Status::ok();
}

}  // namespace icf
