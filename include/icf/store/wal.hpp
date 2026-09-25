// Inter-Cluster Fabric - integrity-checked append-only log.
//
// File header (64 bytes):
//   0  8  magic "ICFWAL1"
//   8  2  format version
//  10  2  flags (must be zero)
//  12  4  header length
//  16 16  stream incarnation
//  32  8  created-at (unix nanos)
//  40  8  first sequence
//  48  8  reserved (must be zero)
//  56  8  header CRC32C over bytes [0,56)
//
// Record:
//   0  4  payload length       (<= limits::kMaxStoreRecordPayload)
//   4  2  record kind
//   6  2  flags (must be zero)
//   8  8  sequence
//  16  8  timestamp (unix nanos)
//  24  4  payload CRC32C
//  28  4  header CRC32C over bytes [0,28)
//  32  N  payload
//  32+N 4  record CRC32C over bytes [0,32+N)
//
// Recovery is conservative: the first record that cannot be verified ends the trusted prefix,
// and everything from that offset is discarded and reported as an incident. Authorization state
// can therefore only shrink across a recovery, never appear from damaged bytes. Malformed file
// headers, unsupported format versions, and sequence regressions are refused outright.
#pragma once

#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <vector>

#include "icf/core/bytes.hpp"
#include "icf/core/status.hpp"
#include "icf/core/time.hpp"

namespace icf::store {

enum class RecordKind : std::uint16_t {
  Invalid = 0,
  Mutation = 1,        // an authoritative state mutation
  Meta = 2,            // term / incarnation metadata
  SnapshotMarker = 3,  // records that a snapshot was taken at this sequence
  Incident = 4,        // a recovery incident preserved for the audit trail
};

[[nodiscard]] const char* to_string(RecordKind kind) noexcept;
[[nodiscard]] bool record_kind_known(RecordKind kind) noexcept;

inline constexpr std::size_t kWalHeaderSize = 64;
inline constexpr std::size_t kRecordHeaderSize = 32;
inline constexpr std::size_t kRecordTrailerSize = 4;
inline constexpr std::uint16_t kWalFormatVersion = 1;

struct RecordHeader {
  std::uint32_t length = 0;
  RecordKind kind = RecordKind::Invalid;
  std::uint16_t flags = 0;
  Sequence sequence;
  Timestamp at{};
  std::uint32_t payload_crc = 0;
  std::uint32_t header_crc = 0;
};

struct WalOptions {
  std::string path;
  std::uint64_t max_bytes = 0;  // 0 selects limits::kMaxStoreBytes
  std::uint64_t max_records = 0;
  bool durable = true;
};

struct WalRecovery {
  bool created = false;
  bool truncated_tail = false;
  std::uint64_t records = 0;
  std::uint64_t bytes = 0;
  std::uint64_t discarded_bytes = 0;
  Sequence last_sequence;
  std::vector<std::string> incidents;
};

class Wal {
 public:
  using Visitor = std::function<Status(const RecordHeader&, std::span<const std::byte>)>;

  Wal() = default;
  Wal(Wal&&) noexcept = default;
  Wal& operator=(Wal&&) noexcept = default;
  Wal(const Wal&) = delete;
  Wal& operator=(const Wal&) = delete;

  // Opens or creates the log and scans every intact record in sequence order.
  [[nodiscard]] static Result<Wal> open(const WalOptions& options, const Visitor& visitor, WalRecovery& recovery);

  [[nodiscard]] Status append(RecordKind kind, Sequence sequence, Timestamp at, std::span<const std::byte> payload);
  // Discards every record, keeping the file header. Used after a snapshot has been made durable.
  [[nodiscard]] Status reset();
  [[nodiscard]] bool needs_compaction(std::uint64_t byte_threshold, std::uint64_t record_threshold) const noexcept;

  [[nodiscard]] std::uint64_t bytes() const noexcept { return bytes_; }
  [[nodiscard]] std::uint64_t records() const noexcept { return records_; }
  [[nodiscard]] Sequence last_sequence() const noexcept { return last_sequence_; }
  [[nodiscard]] const std::string& path() const noexcept { return options_.path; }
  [[nodiscard]] bool valid() const noexcept { return open_; }

 private:
  WalOptions options_;
  std::uint64_t bytes_ = 0;
  std::uint64_t records_ = 0;
  Sequence last_sequence_;
  bool open_ = false;
};

}  // namespace icf::store
