#include "icf/store/wal.hpp"

#include <cstdio>
#include <cstring>

#include "icf/core/checked.hpp"
#include "icf/core/hash.hpp"
#include "icf/core/limits.hpp"
#include "icf/core/rng.hpp"
#include "icf/store/file_util.hpp"

namespace icf::store {
namespace {

constexpr std::array<std::byte, 8> kWalMagic{std::byte{'I'}, std::byte{'C'}, std::byte{'F'}, std::byte{'W'},
                                             std::byte{'A'}, std::byte{'L'}, std::byte{'1'}, std::byte{0}};

IncarnationId new_stream_id() {
  Rng rng(entropy_seed());
  return IncarnationId::random(rng);
}

std::FILE* open_read(const std::string& path) {
  std::FILE* file = nullptr;
#if defined(_WIN32)
  if (fopen_s(&file, path.c_str(), "rb") != 0) {
    return nullptr;
  }
#else
  file = std::fopen(path.c_str(), "rb");
#endif
  return file;
}

std::FILE* open_read_write(const std::string& path, bool create) {
  std::FILE* file = nullptr;
#if defined(_WIN32)
  if (fopen_s(&file, path.c_str(), create ? "wb+" : "rb+") != 0) {
    return nullptr;
  }
#else
  file = std::fopen(path.c_str(), create ? "wb+" : "rb+");
#endif
  return file;
}

void put_u16(std::byte* out, std::uint16_t value) {
  out[0] = static_cast<std::byte>((value >> 8) & 0xFFu);
  out[1] = static_cast<std::byte>(value & 0xFFu);
}

void put_u32(std::byte* out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out[i] = static_cast<std::byte>((value >> (24 - i * 8)) & 0xFFu);
  }
}

void put_u64(std::byte* out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out[i] = static_cast<std::byte>((value >> (56 - i * 8)) & 0xFFu);
  }
}

std::uint16_t get_u16(const std::byte* in) {
  return static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(in[0]) << 8) | std::to_integer<std::uint8_t>(in[1]));
}

std::uint32_t get_u32(const std::byte* in) {
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value = (value << 8) | std::to_integer<std::uint8_t>(in[i]);
  }
  return value;
}

std::uint64_t get_u64(const std::byte* in) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value = (value << 8) | std::to_integer<std::uint8_t>(in[i]);
  }
  return value;
}

std::vector<std::byte> make_header(IncarnationId stream, Timestamp created_at) {
  std::vector<std::byte> header(kWalHeaderSize, std::byte{0});
  std::memcpy(header.data(), kWalMagic.data(), kWalMagic.size());
  put_u16(header.data() + 8, kWalFormatVersion);
  put_u16(header.data() + 10, 0);
  put_u32(header.data() + 12, static_cast<std::uint32_t>(kWalHeaderSize));
  std::memcpy(header.data() + 16, stream.uuid().bytes().data(), 16);
  put_u64(header.data() + 32, static_cast<std::uint64_t>(created_at.unix_nanos()));
  put_u64(header.data() + 40, 0);
  put_u64(header.data() + 48, 0);
  put_u32(header.data() + 56, crc32c(std::span<const std::byte>(header.data(), 56)));
  put_u32(header.data() + 60, 0);
  return header;
}

Status validate_header(std::span<const std::byte> header) {
  if (header.size() < kWalHeaderSize) {
    return Status::make(Outcome::Incomplete, "log header is shorter than the fixed header size");
  }
  if (std::memcmp(header.data(), kWalMagic.data(), kWalMagic.size()) != 0) {
    return Status::make(Outcome::Corrupt, "log header magic does not match ICFWAL1");
  }
  const std::uint16_t version = get_u16(header.data() + 8);
  if (version != kWalFormatVersion) {
    return Status::make(Outcome::Incompatible, "log format version is not supported");
  }
  if (get_u16(header.data() + 10) != 0) {
    return invalid("log header flags must be zero");
  }
  if (get_u32(header.data() + 12) != static_cast<std::uint32_t>(kWalHeaderSize)) {
    return invalid("log header length field is inconsistent");
  }
  const std::uint32_t declared = get_u32(header.data() + 56);
  if (declared != crc32c(header.first(56))) {
    return Status::make(Outcome::Corrupt, "log header CRC32C mismatch");
  }
  return Status::ok();
}

}  // namespace

const char* to_string(RecordKind kind) noexcept {
  switch (kind) {
    case RecordKind::Invalid:
      return "INVALID";
    case RecordKind::Mutation:
      return "MUTATION";
    case RecordKind::Meta:
      return "META";
    case RecordKind::SnapshotMarker:
      return "SNAPSHOT_MARKER";
    case RecordKind::Incident:
      return "INCIDENT";
  }
  return "INVALID";
}

bool record_kind_known(RecordKind kind) noexcept {
  return kind == RecordKind::Mutation || kind == RecordKind::Meta || kind == RecordKind::SnapshotMarker ||
         kind == RecordKind::Incident;
}

Result<Wal> Wal::open(const WalOptions& options, const Visitor& visitor, WalRecovery& recovery) {
  Wal wal;
  wal.options_ = options;
  if (options.path.empty()) {
    return invalid("log path must not be empty");
  }
  wal.options_.max_bytes = options.max_bytes == 0 ? limits::kMaxStoreBytes : options.max_bytes;
  wal.options_.max_records = options.max_records == 0 ? limits::kMaxStoreRecords : options.max_records;

  if (!file_exists(options.path)) {
    const std::vector<std::byte> header = make_header(new_stream_id(), Timestamp::from_unix_nanos(0));
    const Status written = write_file_atomic(options.path, header);
    if (!written) {
      return written;
    }
    recovery.created = true;
    wal.bytes_ = kWalHeaderSize;
    wal.open_ = true;
    return wal;
  }

  std::FILE* file = open_read(options.path);
  if (file == nullptr) {
    return Status::make(Outcome::NotFound, "cannot open log file: " + options.path);
  }
  std::array<std::byte, kWalHeaderSize> header{};
  const std::size_t header_read = std::fread(header.data(), 1, header.size(), file);
  if (header_read != header.size()) {
    std::fclose(file);
    return Status::make(Outcome::Corrupt, "log file is shorter than the fixed header");
  }
  const Status header_status = validate_header(header);
  if (!header_status) {
    std::fclose(file);
    return header_status;
  }

  std::uint64_t offset = kWalHeaderSize;
  std::uint64_t records = 0;
  Sequence last_sequence;
  Sequence previous;
  bool first_record = true;
  std::uint64_t bad_offset = 0;
  std::string incident;

  for (;;) {
    std::array<std::byte, kRecordHeaderSize> record_header{};
    const std::size_t read = std::fread(record_header.data(), 1, record_header.size(), file);
    if (read == 0) {
      break;  // clean end of log
    }
    if (read != record_header.size()) {
      bad_offset = offset;
      incident = "log ends inside a record header";
      break;
    }
    const std::uint32_t declared_header_crc = get_u32(record_header.data() + 28);
    if (declared_header_crc != crc32c(std::span<const std::byte>(record_header.data(), 28))) {
      bad_offset = offset;
      incident = "record header CRC32C mismatch";
      break;
    }
    const std::uint16_t raw_kind = get_u16(record_header.data() + 4);
    if (!record_kind_known(static_cast<RecordKind>(raw_kind))) {
      bad_offset = offset;
      incident = "record kind is not recognised";
      break;
    }
    if (get_u16(record_header.data() + 6) != 0) {
      bad_offset = offset;
      incident = "record flags must be zero";
      break;
    }
    const std::uint32_t length = get_u32(record_header.data());
    if (length > limits::kMaxStoreRecordPayload) {
      bad_offset = offset;
      incident = "record payload length exceeds the maximum";
      break;
    }
    const Sequence sequence{get_u64(record_header.data() + 8)};
    if (!first_record && !(previous < sequence)) {
      std::fclose(file);
      return Status::make(Outcome::Replayed, "log sequence numbers are not strictly increasing");
    }

    std::vector<std::byte> payload(length);
    if (length > 0 && std::fread(payload.data(), 1, length, file) != length) {
      bad_offset = offset;
      incident = "log ends inside a record payload";
      break;
    }
    std::array<std::byte, kRecordTrailerSize> trailer{};
    if (std::fread(trailer.data(), 1, trailer.size(), file) != trailer.size()) {
      bad_offset = offset;
      incident = "log ends inside a record trailer";
      break;
    }
    std::vector<std::byte> whole;
    whole.reserve(kRecordHeaderSize + length);
    whole.insert(whole.end(), record_header.begin(), record_header.end());
    whole.insert(whole.end(), payload.begin(), payload.end());
    if (get_u32(trailer.data()) != crc32c(whole)) {
      bad_offset = offset;
      incident = "record CRC32C mismatch";
      break;
    }
    if (get_u32(record_header.data() + 24) != crc32c(payload)) {
      bad_offset = offset;
      incident = "record payload CRC32C mismatch";
      break;
    }

    RecordHeader decoded;
    decoded.length = length;
    decoded.kind = static_cast<RecordKind>(raw_kind);
    decoded.flags = 0;
    decoded.sequence = sequence;
    decoded.at = Timestamp::from_unix_nanos(static_cast<std::int64_t>(get_u64(record_header.data() + 16)));
    decoded.payload_crc = get_u32(record_header.data() + 24);
    decoded.header_crc = declared_header_crc;

    const Status visit = visitor(decoded, payload);
    if (!visit) {
      std::fclose(file);
      return visit;
    }
    previous = sequence;
    last_sequence = sequence;
    first_record = false;
    ++records;
    offset += kRecordHeaderSize + length + kRecordTrailerSize;
    if (records > wal.options_.max_records) {
      std::fclose(file);
      return Status::make(Outcome::CapacityExceeded, "log holds more records than the configured bound");
    }
  }

  std::fclose(file);
  std::uint64_t file_bytes = offset;
  Result<std::uint64_t> size = file_size(options.path);
  if (size) {
    file_bytes = size.value();
  }

  if (!incident.empty()) {
    const Status truncated = truncate_file(options.path, bad_offset);
    if (!truncated) {
      return truncated;
    }
    recovery.truncated_tail = true;
    recovery.discarded_bytes = file_bytes > bad_offset ? file_bytes - bad_offset : 0;
    std::string message = incident;
    message += " at offset ";
    message += std::to_string(bad_offset);
    message += "; discarded ";
    message += std::to_string(recovery.discarded_bytes);
    message += " bytes";
    recovery.incidents.push_back(message);
    file_bytes = bad_offset;
  }

  wal.bytes_ = file_bytes;
  wal.records_ = records;
  wal.last_sequence_ = last_sequence;
  wal.open_ = true;
  recovery.records = records;
  recovery.bytes = file_bytes;
  recovery.last_sequence = last_sequence;
  return wal;
}

Status Wal::append(RecordKind kind, Sequence sequence, Timestamp at, std::span<const std::byte> payload) {
  if (!open_) {
    return Status::make(Outcome::Internal, "log is not open");
  }
  if (!record_kind_known(kind)) {
    return invalid("record kind is not recognised");
  }
  if (payload.size() > limits::kMaxStoreRecordPayload) {
    return Status::make(Outcome::CapacityExceeded, "record payload exceeds the maximum size");
  }
  if (records_ >= options_.max_records) {
    return Status::make(Outcome::CapacityExceeded, "log reached the configured record bound");
  }
  std::size_t added = 0;
  if (!checked::add_size(kRecordHeaderSize + kRecordTrailerSize, payload.size(), added) ||
      !checked::add_size(added, bytes_, added)) {
    return Status::make(Outcome::Overflow, "record size computation overflow");
  }
  if (added > options_.max_bytes) {
    return Status::make(Outcome::CapacityExceeded, "log reached the configured size bound");
  }

  std::vector<std::byte> bytes;
  bytes.resize(kRecordHeaderSize + payload.size() + kRecordTrailerSize);
  put_u32(bytes.data(), static_cast<std::uint32_t>(payload.size()));
  put_u16(bytes.data() + 4, static_cast<std::uint16_t>(kind));
  put_u16(bytes.data() + 6, 0);
  put_u64(bytes.data() + 8, sequence.value());
  put_u64(bytes.data() + 16, static_cast<std::uint64_t>(at.unix_nanos()));
  put_u32(bytes.data() + 24, crc32c(payload));
  put_u32(bytes.data() + 28, crc32c(std::span<const std::byte>(bytes.data(), 28)));
  if (!payload.empty()) {
    std::memcpy(bytes.data() + kRecordHeaderSize, payload.data(), payload.size());
  }
  put_u32(bytes.data() + kRecordHeaderSize + payload.size(), crc32c(std::span<const std::byte>(bytes.data(),
                                                                                             kRecordHeaderSize + payload.size())));
  const Status appended = append_file(options_.path, bytes, options_.durable);
  if (!appended) {
    return appended;
  }
  bytes_ += bytes.size();
  ++records_;
  last_sequence_ = sequence;
  return Status::ok();
}

Status Wal::reset() {
  if (!open_) {
    return Status::make(Outcome::Internal, "log is not open");
  }
  const std::vector<std::byte> header = make_header(new_stream_id(), Timestamp::from_unix_nanos(0));
  const Status written = write_file_atomic(options_.path, header);
  if (!written) {
    return written;
  }
  bytes_ = header.size();
  records_ = 0;
  return Status::ok();
}

bool Wal::needs_compaction(std::uint64_t byte_threshold, std::uint64_t record_threshold) const noexcept {
  return bytes_ >= byte_threshold || records_ >= record_threshold;
}

}  // namespace icf::store
