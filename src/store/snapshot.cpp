#include "icf/store/snapshot.hpp"

#include <cstring>

#include "icf/core/checked.hpp"
#include "icf/core/hash.hpp"
#include "icf/core/limits.hpp"
#include "icf/store/file_util.hpp"

namespace icf::store {
namespace {

constexpr std::array<std::byte, 8> kSnapshotMagic{std::byte{'I'}, std::byte{'C'}, std::byte{'F'}, std::byte{'S'},
                                                  std::byte{'N'}, std::byte{'P'}, std::byte{'1'}, std::byte{0}};

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

}  // namespace

Result<std::vector<std::byte>> encode_snapshot(const StoreMeta& meta, const model::Registry& registry) {
  ByteWriter payload;
  model::encode_registry(registry, payload, true);
  if (payload.size() > limits::kMaxStoreRecordPayload) {
    return Status::make(Outcome::CapacityExceeded, "snapshot payload exceeds the maximum record size");
  }

  std::vector<std::byte> bytes(kSnapshotHeaderSize + payload.size() + 4, std::byte{0});
  std::memcpy(bytes.data(), kSnapshotMagic.data(), kSnapshotMagic.size());
  put_u16(bytes.data() + 8, kSnapshotFormatVersion);
  put_u16(bytes.data() + 10, 0);
  put_u32(bytes.data() + 12, static_cast<std::uint32_t>(payload.size()));
  put_u32(bytes.data() + 16, crc32c(payload.data()));
  put_u32(bytes.data() + 20, crc32c(std::span<const std::byte>(bytes.data(), 20)));
  std::memcpy(bytes.data() + 24, meta.incarnation.uuid().bytes().data(), 16);
  put_u64(bytes.data() + 40, meta.term.value());
  put_u64(bytes.data() + 48, meta.revision.value());
  put_u64(bytes.data() + 56, meta.sequence.value());
  put_u64(bytes.data() + 64, static_cast<std::uint64_t>(meta.written_at.unix_nanos()));
  put_u64(bytes.data() + 72, meta.truncations);
  std::memcpy(bytes.data() + 80, registry.digest().bytes().data(), Digest::kSize);
  if (!payload.data().empty()) {
    std::memcpy(bytes.data() + kSnapshotHeaderSize, payload.data().data(), payload.size());
  }
  put_u32(bytes.data() + kSnapshotHeaderSize + payload.size(),
          crc32c(std::span<const std::byte>(bytes.data(), kSnapshotHeaderSize + payload.size())));
  return bytes;
}

Result<Snapshot> decode_snapshot(std::span<const std::byte> bytes) {
  if (bytes.size() < kSnapshotHeaderSize + 4) {
    return Status::make(Outcome::Incomplete, "snapshot is shorter than the fixed header");
  }
  if (std::memcmp(bytes.data(), kSnapshotMagic.data(), kSnapshotMagic.size()) != 0) {
    return Status::make(Outcome::Corrupt, "snapshot magic does not match ICFSNP1");
  }
  const std::uint16_t version = get_u16(bytes.data() + 8);
  if (version != kSnapshotFormatVersion) {
    return Status::make(Outcome::Incompatible, "snapshot format version is not supported");
  }
  if (get_u16(bytes.data() + 10) != 0) {
    return invalid("snapshot flags must be zero");
  }
  if (get_u32(bytes.data() + 20) != crc32c(bytes.first(20))) {
    return Status::make(Outcome::Corrupt, "snapshot header CRC32C mismatch");
  }
  const std::uint32_t payload_length = get_u32(bytes.data() + 12);
  if (payload_length > limits::kMaxStoreRecordPayload) {
    return Status::make(Outcome::CapacityExceeded, "snapshot payload exceeds the maximum record size");
  }
  std::size_t total = 0;
  if (!checked::add_size(kSnapshotHeaderSize, payload_length, total) || !checked::add_size(total, 4, total)) {
    return Status::make(Outcome::Overflow, "snapshot length computation overflow");
  }
  if (bytes.size() != total) {
    return Status::make(Outcome::Incomplete, "snapshot length does not match the declared payload length");
  }
  const std::span<const std::byte> payload = bytes.subspan(kSnapshotHeaderSize, payload_length);
  if (get_u32(bytes.data() + kSnapshotHeaderSize + payload_length) !=
      crc32c(bytes.first(kSnapshotHeaderSize + payload_length))) {
    return Status::make(Outcome::Corrupt, "snapshot record CRC32C mismatch");
  }
  if (get_u32(bytes.data() + 16) != crc32c(payload)) {
    return Status::make(Outcome::Corrupt, "snapshot payload CRC32C mismatch");
  }

  ByteReader reader(payload);
  Result<model::Registry> registry = model::decode_registry(reader);
  if (!registry) {
    return registry.status();
  }

  Snapshot snapshot;
  snapshot.registry = std::move(registry.value());
  snapshot.meta.incarnation = IncarnationId::from_uuid(Uuid::from_bytes(bytes.subspan(24, 16)));
  snapshot.meta.term = Term(get_u64(bytes.data() + 40));
  snapshot.meta.revision = Revision(get_u64(bytes.data() + 48));
  snapshot.meta.sequence = Sequence(get_u64(bytes.data() + 56));
  snapshot.meta.written_at = Timestamp::from_unix_nanos(static_cast<std::int64_t>(get_u64(bytes.data() + 64)));
  snapshot.meta.truncations = get_u64(bytes.data() + 72);
  const Digest declared = Digest::from_bytes(bytes.subspan(80, Digest::kSize));
  const Digest actual = snapshot.registry.digest();
  if (declared != actual) {
    return Status::make(Outcome::Corrupt, "snapshot contents do not match the digest recorded in the header");
  }
  snapshot.meta.state_digest = actual;
  return snapshot;
}

Status save_snapshot(const std::string& path, const StoreMeta& meta, const model::Registry& registry) {
  Result<std::vector<std::byte>> bytes = encode_snapshot(meta, registry);
  if (!bytes) {
    return bytes.status();
  }
  return write_file_atomic(path, bytes.value());
}

Result<Snapshot> load_snapshot(const std::string& path) {
  Result<std::vector<std::byte>> bytes = read_file_bounded(path, limits::kMaxStoreRecordPayload + kSnapshotHeaderSize + 4);
  if (!bytes) {
    return bytes.status();
  }
  return decode_snapshot(bytes.value());
}

}  // namespace icf::store
