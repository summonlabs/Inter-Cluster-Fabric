// Inter-Cluster Fabric - bounded big-endian byte codec.
//
// All fixed-width integers are encoded big-endian so that digests and wire frames are
// identical on every host. Readers validate length prefixes against explicit maxima
// *before* allocating, and every arithmetic step is checked.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "icf/core/hash.hpp"
#include "icf/core/ids.hpp"
#include "icf/core/status.hpp"

namespace icf {

class ByteWriter {
 public:
  ByteWriter() = default;

  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void i64(std::int64_t value);
  void boolean(bool value);
  void raw(std::span<const std::byte> data);
  void blob(std::string_view text);  // u32 byte length + raw bytes
  void uuid(const Uuid& value);
  void digest(const Digest& value);

  // Returns false (and writes nothing) when the count does not fit in the u32 field.
  [[nodiscard]] bool count(std::size_t value);

  [[nodiscard]] const std::vector<std::byte>& data() const noexcept { return data_; }
  [[nodiscard]] std::vector<std::byte> take() && { return std::move(data_); }
  [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
  void clear() noexcept { data_.clear(); }

 private:
  std::vector<std::byte> data_;
};

class ByteReader {
 public:
  explicit ByteReader(std::span<const std::byte> data) noexcept : data_(data) {}

  [[nodiscard]] Result<std::uint8_t> u8();
  [[nodiscard]] Result<std::uint16_t> u16();
  [[nodiscard]] Result<std::uint32_t> u32();
  [[nodiscard]] Result<std::uint64_t> u64();
  [[nodiscard]] Result<std::int64_t> i64();
  [[nodiscard]] Result<bool> boolean();
  [[nodiscard]] Result<std::span<const std::byte>> raw(std::size_t count);
  [[nodiscard]] Result<std::string> blob(std::size_t max_length);
  [[nodiscard]] Result<Uuid> uuid();
  [[nodiscard]] Result<Digest> digest();
  // Reads a bounded collection count. Rejects counts above max_count with INVALID rather
  // than attempting the allocation.
  [[nodiscard]] Result<std::size_t> count(std::size_t max_count);

  [[nodiscard]] bool at_end() const noexcept { return offset_ == data_.size(); }
  [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - offset_; }
  [[nodiscard]] std::size_t offset() const noexcept { return offset_; }
  [[nodiscard]] Status expect_end() const;

 private:
  std::span<const std::byte> data_;
  std::size_t offset_ = 0;
};

}  // namespace icf
