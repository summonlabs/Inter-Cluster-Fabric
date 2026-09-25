// Inter-Cluster Fabric - snapshot plus write-ahead log.
//
// The coordinator owns one durable store (authoritative cross-cluster state) and every cluster
// agent owns one (its own incarnation, generation, consents, and enforcement records). Both use
// the same format: a snapshot for the bulk state and a log for everything since.
//
// Recovery order: snapshot, then log records in sequence order. A recovered store is always
// reported as recovered-from-store, which marks every dynamic record inside it as historical
// evidence that must be revalidated with the authority that produced it.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "icf/store/snapshot.hpp"
#include "icf/store/wal.hpp"

namespace icf::store {

class DurableStore {
 public:
  struct Options {
    std::string directory;
    std::string snapshot_name = "state.snapshot";
    std::string wal_name = "state.wal";
    std::uint64_t compact_bytes = 4u << 20;
    std::uint64_t compact_records = 8192;
    bool durable = true;
  };

  struct Recovery {
    model::Registry registry;
    StoreMeta meta;
    WalRecovery wal;
    bool snapshot_loaded = false;
    bool recovered_from_store = false;
    bool created_fresh = false;
    std::uint64_t mutations_applied = 0;
    std::vector<std::string> incidents;
  };

  DurableStore() = default;
  DurableStore(DurableStore&&) noexcept = default;
  DurableStore& operator=(DurableStore&&) noexcept = default;
  DurableStore(const DurableStore&) = delete;
  DurableStore& operator=(const DurableStore&) = delete;

  [[nodiscard]] static Result<DurableStore> open(const Options& options, Recovery& recovery);

  [[nodiscard]] Result<Sequence> append(const Mutation& mutation, Timestamp at);
  [[nodiscard]] Result<Sequence> append_meta(const StoreMeta& meta, Timestamp at);
  [[nodiscard]] Result<Sequence> append_incident(const std::string& text, Timestamp at);
  // Writes the snapshot, then discards the log records it covers. The order matters: the
  // snapshot must be durable before the log is truncated.
  [[nodiscard]] Status compact(const model::Registry& registry, const StoreMeta& meta, Timestamp at);

  [[nodiscard]] bool needs_compaction() const noexcept;
  [[nodiscard]] const Options& options() const noexcept { return options_; }
  [[nodiscard]] std::uint64_t wal_bytes() const noexcept { return wal_.bytes(); }
  [[nodiscard]] std::uint64_t wal_records() const noexcept { return wal_.records(); }
  [[nodiscard]] Sequence last_sequence() const noexcept { return wal_.last_sequence(); }
  [[nodiscard]] std::string snapshot_path() const;
  [[nodiscard]] std::string wal_path() const;
  [[nodiscard]] bool valid() const noexcept { return open_; }

 private:
  Options options_;
  Wal wal_;
  Sequence next_sequence_;
  bool open_ = false;
};

}  // namespace icf::store
