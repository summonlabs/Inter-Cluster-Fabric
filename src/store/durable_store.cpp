#include "icf/store/durable_store.hpp"

#include "icf/core/limits.hpp"
#include "icf/store/file_util.hpp"

namespace icf::store {

std::string DurableStore::snapshot_path() const { return join_path(options_.directory, options_.snapshot_name); }

std::string DurableStore::wal_path() const { return join_path(options_.directory, options_.wal_name); }

Result<DurableStore> DurableStore::open(const Options& options, Recovery& recovery) {
  DurableStore store;
  store.options_ = options;
  if (options.directory.empty()) {
    return invalid("store directory must not be empty");
  }
  const Status directory = ensure_directory(options.directory);
  if (!directory) {
    return directory;
  }

  const std::string snapshot_file = join_path(options.directory, options.snapshot_name);
  const std::string wal_file_probe = join_path(options.directory, options.wal_name);
  const bool had_state = file_exists(snapshot_file) || file_exists(wal_file_probe);
  if (file_exists(snapshot_file)) {
    Result<Snapshot> snapshot = load_snapshot(snapshot_file);
    if (!snapshot) {
      return snapshot.status();
    }
    recovery.registry = std::move(snapshot.value().registry);
    recovery.meta = snapshot.value().meta;
    recovery.snapshot_loaded = true;
  } else if (!had_state) {
    // Only a store with neither a snapshot nor a log is a fresh store; a missing snapshot with a
    // live log is a recovered store, and reporting it as fresh would hide recovered evidence.
    recovery.created_fresh = true;
  }

  const std::string wal_file = join_path(options.directory, options.wal_name);
  WalOptions wal_options;
  wal_options.path = wal_file;
  wal_options.durable = options.durable;

  Wal::Visitor visitor = [&recovery](const RecordHeader& header, std::span<const std::byte> payload) -> Status {
    switch (header.kind) {
      case RecordKind::Mutation: {
        ByteReader reader(payload);
        Result<Mutation> mutation = decode_mutation(reader);
        if (!mutation) {
          return mutation.status();
        }
        const Status end = reader.expect_end();
        if (!end) {
          return end;
        }
        if (mutation.value().kind == MutationKind::MetaSet) {
          recovery.meta.term = mutation.value().meta_term;
          recovery.meta.incarnation = mutation.value().meta_incarnation;
          return Status::ok();
        }
        const Status applied = apply_mutation(recovery.registry, mutation.value());
        if (!applied) {
          return applied;
        }
        ++recovery.mutations_applied;
        return Status::ok();
      }
      case RecordKind::Meta: {
        ByteReader reader(payload);
        Result<std::uint64_t> term = reader.u64();
        if (!term) {
          return term.status();
        }
        if (term.value() > limits::kMaxGeneration) {
          return Status::make(Outcome::Overflow, "term exceeds the maximum supported value");
        }
        Result<Uuid> incarnation = reader.uuid();
        if (!incarnation) {
          return incarnation.status();
        }
        recovery.meta.term = Term(term.value());
        recovery.meta.incarnation = IncarnationId::from_uuid(incarnation.value());
        return Status::ok();
      }
      case RecordKind::SnapshotMarker:
        return Status::ok();
      case RecordKind::Incident:
        if (recovery.incidents.size() < 64) {
          recovery.incidents.emplace_back(reinterpret_cast<const char*>(payload.data()), payload.size());
        }
        return Status::ok();
      case RecordKind::Invalid:
        return invalid("log record kind is not recognised");
    }
    return invalid("log record kind is not recognised");
  };

  Result<Wal> wal = Wal::open(wal_options, visitor, recovery.wal);
  if (!wal) {
    return wal.status();
  }
  store.wal_ = std::move(wal.value());
  recovery.meta.sequence = recovery.wal.last_sequence;
  recovery.recovered_from_store = recovery.snapshot_loaded || recovery.wal.records > 0;
  if (recovery.wal.truncated_tail) {
    ++recovery.meta.truncations;
    for (const std::string& incident : recovery.wal.incidents) {
      if (recovery.incidents.size() < 64) {
        recovery.incidents.push_back(incident);
      }
    }
  }
  const Sequence last = recovery.wal.last_sequence;
  store.next_sequence_ = last.next().has_value() ? last.next().value() : Sequence(UINT64_MAX);
  if (last.is_zero()) {
    store.next_sequence_ = Sequence(1);
  }
  store.open_ = true;
  recovery.meta.written_at = Timestamp::from_unix_nanos(0);
  return store;
}

Result<Sequence> DurableStore::append(const Mutation& mutation, Timestamp at) {
  if (!open_) {
    return Status::make(Outcome::Internal, "store is not open");
  }
  ByteWriter writer;
  encode_mutation(mutation, writer);
  const Sequence sequence = next_sequence_;
  const Status appended = wal_.append(RecordKind::Mutation, sequence, at, writer.data());
  if (!appended) {
    return appended;
  }
  const Result<Sequence> next = sequence.next();
  next_sequence_ = next ? next.value() : Sequence(UINT64_MAX);
  return sequence;
}

Result<Sequence> DurableStore::append_meta(const StoreMeta& meta, Timestamp at) {
  Mutation mutation;
  mutation.kind = MutationKind::MetaSet;
  mutation.meta_term = meta.term;
  mutation.meta_incarnation = meta.incarnation;
  return append(mutation, at);
}

Result<Sequence> DurableStore::append_incident(const std::string& text, Timestamp at) {
  if (!open_) {
    return Status::make(Outcome::Internal, "store is not open");
  }
  if (text.size() > limits::kMaxStoreRecordPayload) {
    return Status::make(Outcome::CapacityExceeded, "incident text exceeds the maximum record size");
  }
  const std::span<const std::byte> payload(reinterpret_cast<const std::byte*>(text.data()), text.size());
  const Sequence sequence = next_sequence_;
  const Status appended = wal_.append(RecordKind::Incident, sequence, at, payload);
  if (!appended) {
    return appended;
  }
  const Result<Sequence> next = sequence.next();
  next_sequence_ = next ? next.value() : Sequence(UINT64_MAX);
  return sequence;
}

Status DurableStore::compact(const model::Registry& registry, const StoreMeta& meta, Timestamp at) {
  if (!open_) {
    return Status::make(Outcome::Internal, "store is not open");
  }
  StoreMeta effective = meta;
  effective.sequence = wal_.last_sequence();
  effective.written_at = at;
  effective.state_digest = registry.digest();
  const Status saved = save_snapshot(snapshot_path(), effective, registry);
  if (!saved) {
    return saved;
  }
  return wal_.reset();
}

bool DurableStore::needs_compaction() const noexcept {
  return wal_.needs_compaction(options_.compact_bytes, options_.compact_records);
}

}  // namespace icf::store
