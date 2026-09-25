#include "icf/wire/frame.hpp"

#include <cstring>

#include "icf/core/bytes.hpp"
#include "icf/core/checked.hpp"
#include "icf/core/hash.hpp"
#include "icf/core/limits.hpp"

namespace icf::wire {
namespace {

void write_u16(std::byte* out, std::uint16_t value) {
  out[0] = static_cast<std::byte>((value >> 8) & 0xFFu);
  out[1] = static_cast<std::byte>(value & 0xFFu);
}

void write_u32(std::byte* out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out[i] = static_cast<std::byte>((value >> (24 - i * 8)) & 0xFFu);
  }
}

std::uint16_t read_u16(const std::byte* in) {
  return static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(in[0]) << 8) |
                                    std::to_integer<std::uint8_t>(in[1]));
}

std::uint32_t read_u32(const std::byte* in) {
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value = (value << 8) | std::to_integer<std::uint8_t>(in[i]);
  }
  return value;
}

}  // namespace

const char* to_string(MessageType type) noexcept {
  switch (type) {
    case MessageType::Invalid:
      return "INVALID";
    case MessageType::Hello:
      return "HELLO";
    case MessageType::HelloAck:
      return "HELLO_ACK";
    case MessageType::Refuse:
      return "REFUSE";
    case MessageType::Ping:
      return "PING";
    case MessageType::Pong:
      return "PONG";
    case MessageType::ReportCluster:
      return "REPORT_CLUSTER";
    case MessageType::ReportAck:
      return "REPORT_ACK";
    case MessageType::ProposeContract:
      return "PROPOSE_CONTRACT";
    case MessageType::ContractConsent:
      return "CONTRACT_CONSENT";
    case MessageType::PrepareGrant:
      return "PREPARE_GRANT";
    case MessageType::GrantPrepared:
      return "GRANT_PREPARED";
    case MessageType::CommitGrant:
      return "COMMIT_GRANT";
    case MessageType::GrantCommitted:
      return "GRANT_COMMITTED";
    case MessageType::AbortGrant:
      return "ABORT_GRANT";
    case MessageType::GrantAborted:
      return "GRANT_ABORTED";
    case MessageType::Fence:
      return "FENCE";
    case MessageType::FenceAck:
      return "FENCE_ACK";
    case MessageType::Withdraw:
      return "WITHDRAW";
    case MessageType::WithdrawAck:
      return "WITHDRAW_ACK";
    case MessageType::StatusRequest:
      return "STATUS_REQUEST";
    case MessageType::StatusReport:
      return "STATUS_REPORT";
    case MessageType::Query:
      return "QUERY";
    case MessageType::QueryResult:
      return "QUERY_RESULT";
    case MessageType::Admin:
      return "ADMIN";
    case MessageType::AdminResult:
      return "ADMIN_RESULT";
    case MessageType::Error:
      return "ERROR";
  }
  return "INVALID";
}

bool message_type_from_string(std::string_view text, MessageType& out) noexcept {
  for (std::uint16_t value = 0; value <= static_cast<std::uint16_t>(MessageType::MaxValue); ++value) {
    const auto candidate = static_cast<MessageType>(value);
    if (text == to_string(candidate)) {
      out = candidate;
      return true;
    }
  }
  return false;
}

bool message_type_known(MessageType type) noexcept {
  return type != MessageType::Invalid && type <= MessageType::MaxValue;
}

std::size_t frame_wire_size(std::uint32_t payload_length, bool signed_frame) noexcept {
  std::size_t size = limits::kFrameHeaderSize + limits::kFrameTrailerSize;
  size += payload_length;
  if (signed_frame) {
    size += kMacSize;
  }
  return size;
}

std::array<std::byte, limits::kFrameHeaderSize> encode_frame_header(const FrameHeader& header) noexcept {
  std::array<std::byte, limits::kFrameHeaderSize> out{};
  std::memcpy(out.data(), kMagic.data(), kMagic.size());
  write_u16(out.data() + 4, header.version);
  write_u16(out.data() + 6, static_cast<std::uint16_t>(header.type));
  write_u32(out.data() + 8, header.flags);
  write_u32(out.data() + 12, header.payload_length);
  const std::uint32_t crc = crc32c(std::span<const std::byte>(out.data(), 16));
  write_u32(out.data() + 16, crc);
  return out;
}

Result<FrameHeader> decode_frame_header(std::span<const std::byte> header) noexcept {
  if (header.size() < limits::kFrameHeaderSize) {
    return Status::make(Outcome::Incomplete, "frame header is shorter than 20 bytes");
  }
  if (std::memcmp(header.data(), kMagic.data(), kMagic.size()) != 0) {
    return invalid("frame magic does not match ICF1");
  }
  const std::uint32_t declared_crc = read_u32(header.data() + 16);
  const std::uint32_t actual_crc = crc32c(header.first(16));
  if (declared_crc != actual_crc) {
    return Status::make(Outcome::Corrupt, "frame header CRC32C mismatch");
  }
  FrameHeader result;
  result.version = read_u16(header.data() + 4);
  if (result.version < limits::kProtocolVersionMin || result.version > limits::kProtocolVersionMax) {
    return Status::make(Outcome::Incompatible, "frame protocol version is not supported");
  }
  const std::uint16_t raw_type = read_u16(header.data() + 6);
  result.type = static_cast<MessageType>(raw_type);
  if (!message_type_known(result.type)) {
    return invalid("frame message type is not recognised");
  }
  result.flags = read_u32(header.data() + 8);
  if ((result.flags & ~kKnownFlags) != 0) {
    return invalid("frame carries unknown flags");
  }
  result.payload_length = read_u32(header.data() + 12);
  if (result.payload_length > limits::kMaxFramePayload) {
    return invalid("frame payload length exceeds the maximum");
  }
  return result;
}

Status append_frame(std::vector<std::byte>& out, const FrameHeader& header, std::span<const std::byte> payload,
                    std::span<const std::byte> key) {
  if (payload.size() > limits::kMaxFramePayload) {
    return invalid("frame payload exceeds the maximum");
  }
  const bool signed_frame = (header.flags & kFlagSigned) != 0;
  if (signed_frame && key.empty()) {
    return invalid("a signed frame requires a channel key");
  }
  const Result<std::size_t> total = checked_sum(frame_wire_size(static_cast<std::uint32_t>(payload.size()), signed_frame), out.size());
  if (!total) {
    return total.status();
  }
  FrameHeader effective = header;
  effective.payload_length = static_cast<std::uint32_t>(payload.size());

  const std::size_t start = out.size();
  const auto encoded_header = encode_frame_header(effective);
  out.insert(out.end(), encoded_header.begin(), encoded_header.end());
  out.insert(out.end(), payload.begin(), payload.end());
  std::byte crc_bytes[4];
  write_u32(crc_bytes, crc32c(payload));
  out.insert(out.end(), crc_bytes, crc_bytes + 4);
  if (signed_frame) {
    const std::size_t covered = limits::kFrameHeaderSize + payload.size() + limits::kFrameTrailerSize;
    const Digest mac = hmac_sha256(key, std::span<const std::byte>(out.data() + start, covered));
    out.insert(out.end(), mac.bytes().begin(), mac.bytes().end());
  }
  return Status::ok();
}

FrameParser::FrameParser(std::uint32_t max_payload) noexcept
    : max_payload_(max_payload > limits::kMaxFramePayload ? limits::kMaxFramePayload : max_payload) {}

Status FrameParser::push(std::span<const std::byte> data) {
  const std::size_t bound = static_cast<std::size_t>(max_payload_) + limits::kFrameHeaderSize +
                            limits::kFrameTrailerSize + kMacSize;
  const Result<std::size_t> total = checked_sum(buffer_.size(), data.size());
  if (!total) {
    return total.status();
  }
  if (total.value() > bound) {
    return invalid("framed input exceeds the maximum frame size");
  }
  buffer_.insert(buffer_.end(), data.begin(), data.end());
  return Status::ok();
}

Result<std::optional<Frame>> FrameParser::next(std::span<const std::byte> key) {
  if (buffer_.size() < limits::kFrameHeaderSize) {
    return std::optional<Frame>{};
  }
  Result<FrameHeader> header = decode_frame_header(std::span<const std::byte>(buffer_.data(), limits::kFrameHeaderSize));
  if (!header) {
    return header.status();
  }
  const bool signed_frame = (header.value().flags & kFlagSigned) != 0;
  if (signed_frame && key.empty()) {
    return invalid("received a signed frame but no channel key is configured");
  }
  if (!signed_frame && !key.empty()) {
    return invalid("received an unsigned frame on a channel that requires signing");
  }
  const std::size_t total = frame_wire_size(header.value().payload_length, signed_frame);
  if (buffer_.size() < total) {
    return std::optional<Frame>{};
  }
  const auto* base = buffer_.data();
  const std::span<const std::byte> payload(base + limits::kFrameHeaderSize, header.value().payload_length);
  const std::uint32_t declared_crc = read_u32(base + limits::kFrameHeaderSize + header.value().payload_length);
  if (declared_crc != crc32c(payload)) {
    return Status::make(Outcome::Corrupt, "frame payload CRC32C mismatch");
  }
  if (signed_frame) {
    const Digest expected = hmac_sha256(key, std::span<const std::byte>(base, limits::kFrameHeaderSize +
                                                                                  header.value().payload_length +
                                                                                  limits::kFrameTrailerSize));
    const std::span<const std::byte> received(base + total - kMacSize, kMacSize);
    if (!constant_time_equal(expected.bytes(), received)) {
      return Status::make(Outcome::Unauthorized, "frame MAC does not verify under the channel key");
    }
  }
  Frame frame;
  frame.header = header.value();
  frame.signed_frame = signed_frame;
  frame.payload.assign(payload.begin(), payload.end());
  buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(total));
  return std::optional<Frame>{std::move(frame)};
}

}  // namespace icf::wire
