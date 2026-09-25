// Inter-Cluster Fabric - framed transport codec.
//
// Frame layout (all integers big-endian):
//   0  magic "ICF1"          4 bytes
//   4  protocol version      u16
//   6  message type          u16
//   8  flags                 u32
//  12  payload length        u32   (<= limits::kMaxFramePayload)
//  16  header CRC32C         u32   over bytes [0,16)
//  20  payload               N bytes
//  20+N payload CRC32C       u32
//  24+N HMAC-SHA256 tag      32 bytes, present only when kFlagSigned is set
//
// The parser validates the declared length against the configured maximum *before* allocating,
// rejects unknown flags and unsupported versions as distinct outcomes, and never trusts a
// length prefix.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "icf/core/byte_limits.hpp"
#include "icf/core/ids.hpp"
#include "icf/core/status.hpp"

namespace icf::wire {

inline constexpr std::uint32_t kFlagSigned = 0x00000001u;
inline constexpr std::uint32_t kKnownFlags = kFlagSigned;
inline constexpr std::size_t kMacSize = 32;
inline constexpr std::array<std::byte, 4> kMagic{std::byte{'I'}, std::byte{'C'}, std::byte{'F'}, std::byte{'1'}};

enum class MessageType : std::uint16_t {
  Invalid = 0,
  Hello = 1,
  HelloAck = 2,
  Refuse = 3,
  Ping = 4,
  Pong = 5,
  ReportCluster = 6,
  ReportAck = 7,
  ProposeContract = 8,
  ContractConsent = 9,
  PrepareGrant = 10,
  GrantPrepared = 11,
  CommitGrant = 12,
  GrantCommitted = 13,
  AbortGrant = 14,
  GrantAborted = 15,
  Fence = 16,
  FenceAck = 17,
  Withdraw = 18,
  WithdrawAck = 19,
  StatusRequest = 20,
  StatusReport = 21,
  Query = 22,
  QueryResult = 23,
  Admin = 24,
  AdminResult = 25,
  Error = 26,
  MaxValue = Error,
};

[[nodiscard]] const char* to_string(MessageType type) noexcept;
[[nodiscard]] bool message_type_from_string(std::string_view text, MessageType& out) noexcept;
[[nodiscard]] bool message_type_known(MessageType type) noexcept;

struct FrameHeader {
  std::uint16_t version = 0;
  MessageType type = MessageType::Invalid;
  std::uint32_t flags = 0;
  std::uint32_t payload_length = 0;
};

struct Frame {
  FrameHeader header;
  std::vector<std::byte> payload;
  bool signed_frame = false;
};

[[nodiscard]] std::size_t frame_wire_size(std::uint32_t payload_length, bool signed_frame) noexcept;
[[nodiscard]] std::array<std::byte, limits::kFrameHeaderSize> encode_frame_header(const FrameHeader& header) noexcept;
[[nodiscard]] Result<FrameHeader> decode_frame_header(std::span<const std::byte> header) noexcept;

// Appends a complete frame (header, payload, trailer, optional MAC) to `out`.
[[nodiscard]] Status append_frame(std::vector<std::byte>& out, const FrameHeader& header,
                                 std::span<const std::byte> payload, std::span<const std::byte> key);

// Incremental parser. push() appends received bytes; next() yields whole frames and reports
// malformed input immediately.
class FrameParser {
 public:
  explicit FrameParser(std::uint32_t max_payload = limits::kMaxFramePayload) noexcept;

  [[nodiscard]] Status push(std::span<const std::byte> data);
  [[nodiscard]] Result<std::optional<Frame>> next(std::span<const std::byte> key);

  [[nodiscard]] std::size_t buffered() const noexcept { return buffer_.size(); }
  [[nodiscard]] std::uint32_t max_payload() const noexcept { return max_payload_; }
  void reset() noexcept { buffer_.clear(); }

 private:
  std::vector<std::byte> buffer_;
  std::uint32_t max_payload_;
};

}  // namespace icf::wire
