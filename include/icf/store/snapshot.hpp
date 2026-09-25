// Inter-Cluster Fabric - versioned, integrity-checked snapshots.
//
// Snapshot file layout:
//   0   8  magic "ICFSNP1"
//   8   2  format version
//  10   2  flags (must be zero)
//  12   4  payload length
//  16   4  payload CRC32C
//  20   4  header CRC32C over bytes [0,20)
//  24  16  stream incarnation
//  40   8  term
//  48   8  revision
//  56   8  sequence covered by this snapshot
//  64   8  written-at (unix nanos)
//  72   8  truncations recovered before this snapshot
//  80  32  digest of the registry the snapshot claims to hold
// 112   N  payload (canonical registry encoding, audit included)
// 112+N 4  record CRC32C over bytes [0,112+N)
//
// A snapshot whose declared digest does not match the registry it decodes to is refused: a
// snapshot is only usable when both its bytes and its contents verify.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "icf/store/mutation.hpp"

namespace icf::store {

inline constexpr std::size_t kSnapshotHeaderSize = 112;
inline constexpr std::uint16_t kSnapshotFormatVersion = 1;

struct Snapshot {
  StoreMeta meta;
  model::Registry registry;
};

[[nodiscard]] Result<std::vector<std::byte>> encode_snapshot(const StoreMeta& meta, const model::Registry& registry);
[[nodiscard]] Result<Snapshot> decode_snapshot(std::span<const std::byte> bytes);
[[nodiscard]] Status save_snapshot(const std::string& path, const StoreMeta& meta, const model::Registry& registry);
[[nodiscard]] Result<Snapshot> load_snapshot(const std::string& path);

}  // namespace icf::store
