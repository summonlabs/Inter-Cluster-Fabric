#include <cstdio>
#include <string>
#include <vector>

#include "harness.hpp"
#include "icf/store/durable_store.hpp"
#include "icf/store/file_util.hpp"
#include "icf/store/snapshot.hpp"
#include "icf/store/wal.hpp"
#include "model_builder.hpp"
#include "temp_dir.hpp"

using namespace icf;
using namespace icf::test;

namespace {

std::vector<std::byte> payload_of(const std::string& text) {
  return std::vector<std::byte>(reinterpret_cast<const std::byte*>(text.data()),
                                reinterpret_cast<const std::byte*>(text.data()) + text.size());
}

}  // namespace

ICF_TEST(wal, append_and_scan_round_trip) {
  TempDir directory("wal-roundtrip");
  store::WalOptions options;
  options.path = directory.child("test.wal");
  store::WalRecovery recovery;

  {
    std::vector<std::string> seen;
    Result<store::Wal> wal = store::Wal::open(options, [&seen](const store::RecordHeader& header,
                                                              std::span<const std::byte> payload) {
      seen.emplace_back(reinterpret_cast<const char*>(payload.data()), payload.size());
      (void)header;
      return Status::ok();
    }, recovery);
    ICF_ASSERT_OK(wal.status());
    ICF_EXPECT_TRUE(recovery.created);
    for (int index = 0; index < 8; ++index) {
      const std::string text = "record-" + std::to_string(index);
      ICF_EXPECT_OK(wal.value().append(store::RecordKind::Mutation, Sequence(static_cast<std::uint64_t>(index + 1)),
                                       Timestamp::from_unix_nanos(1000 + index), payload_of(text)));
    }
    ICF_EXPECT_EQ(8ull, wal.value().records());
  }

  std::vector<std::string> seen;
  store::WalRecovery recovered;
  Result<store::Wal> reopened = store::Wal::open(options, [&seen](const store::RecordHeader& header,
                                                                 std::span<const std::byte> payload) {
    (void)header;
    seen.emplace_back(reinterpret_cast<const char*>(payload.data()), payload.size());
    return Status::ok();
  }, recovered);
  ICF_ASSERT_OK(reopened.status());
  ICF_EXPECT_EQ(static_cast<std::size_t>(8), seen.size());
  ICF_EXPECT_EQ(std::string("record-0"), seen.front());
  ICF_EXPECT_EQ(std::string("record-7"), seen.back());
  ICF_EXPECT_EQ(8ull, recovered.records);
  ICF_EXPECT_FALSE(recovered.truncated_tail);
  ICF_EXPECT_EQ(8ull, reopened.value().last_sequence().value());
}

ICF_TEST(wal, torn_tail_is_recovered_conservatively) {
  TempDir directory("wal-torn");
  store::WalOptions options;
  options.path = directory.child("test.wal");
  store::WalRecovery recovery;
  {
    Result<store::Wal> wal = store::Wal::open(options, [](const store::RecordHeader&, std::span<const std::byte>) {
      return Status::ok();
    }, recovery);
    ICF_ASSERT_OK(wal.status());
    for (int index = 0; index < 4; ++index) {
      const std::string text = "record-" + std::to_string(index);
      ICF_EXPECT_OK(wal.value().append(store::RecordKind::Mutation, Sequence(static_cast<std::uint64_t>(index + 1)),
                                       Timestamp::from_unix_nanos(1), payload_of(text)));
    }
  }
  Result<std::uint64_t> size = store::file_size(options.path);
  ICF_ASSERT_OK(size.status());
  // Cut the last record in half: a classic torn write.
  ICF_EXPECT_OK(store::truncate_file(options.path, size.value() - 6));

  std::vector<std::string> seen;
  store::WalRecovery recovered;
  Result<store::Wal> reopened = store::Wal::open(options, [&seen](const store::RecordHeader&, std::span<const std::byte> payload) {
    seen.emplace_back(reinterpret_cast<const char*>(payload.data()), payload.size());
    return Status::ok();
  }, recovered);
  ICF_ASSERT_OK(reopened.status());
  ICF_EXPECT_EQ(static_cast<std::size_t>(3), seen.size());
  ICF_EXPECT_TRUE(recovered.truncated_tail);
  ICF_EXPECT_TRUE(recovered.discarded_bytes > 0);
  ICF_EXPECT_FALSE(recovered.incidents.empty());
  ICF_EXPECT_EQ(3ull, reopened.value().last_sequence().value());
}

ICF_TEST(wal, damaged_payload_stops_the_trusted_prefix) {
  TempDir directory("wal-damaged");
  store::WalOptions options;
  options.path = directory.child("test.wal");
  store::WalRecovery recovery;
  {
    Result<store::Wal> wal = store::Wal::open(options, [](const store::RecordHeader&, std::span<const std::byte>) {
      return Status::ok();
    }, recovery);
    ICF_ASSERT_OK(wal.status());
    for (int index = 0; index < 3; ++index) {
      const std::string text = std::string(64, 'a');
      ICF_EXPECT_OK(wal.value().append(store::RecordKind::Mutation, Sequence(static_cast<std::uint64_t>(index + 1)),
                                       Timestamp::from_unix_nanos(1), payload_of(text)));
    }
  }
  Result<std::vector<std::byte>> bytes = store::read_file_bounded(options.path, 1 << 20);
  ICF_ASSERT_OK(bytes.status());
  std::vector<std::byte> damaged = bytes.value();
  // Flip a byte inside the second record's payload.
  damaged[store::kWalHeaderSize + store::kRecordHeaderSize + store::kRecordHeaderSize + 40] =
      static_cast<std::byte>(std::to_integer<std::uint8_t>(
                                 damaged[store::kWalHeaderSize + store::kRecordHeaderSize + store::kRecordHeaderSize + 40]) ^
                             0xFFu);
  ICF_EXPECT_OK(store::write_file_atomic(options.path, damaged));

  std::vector<std::string> seen;
  store::WalRecovery recovered;
  Result<store::Wal> reopened = store::Wal::open(options, [&seen](const store::RecordHeader&, std::span<const std::byte> payload) {
    seen.emplace_back(reinterpret_cast<const char*>(payload.data()), payload.size());
    return Status::ok();
  }, recovered);
  ICF_ASSERT_OK(reopened.status());
  ICF_EXPECT_EQ(static_cast<std::size_t>(1), seen.size());
  ICF_EXPECT_TRUE(recovered.truncated_tail);
}

ICF_TEST(wal, rejects_malformed_header_version_and_replay) {
  TempDir directory("wal-header");
  store::WalOptions options;
  options.path = directory.child("test.wal");
  store::WalRecovery recovery;
  {
    Result<store::Wal> wal = store::Wal::open(options, [](const store::RecordHeader&, std::span<const std::byte>) {
      return Status::ok();
    }, recovery);
    ICF_ASSERT_OK(wal.status());
  }
  Result<std::vector<std::byte>> original = store::read_file_bounded(options.path, 1 << 20);
  ICF_ASSERT_OK(original.status());

  std::vector<std::byte> bad_magic = original.value();
  bad_magic[0] = std::byte{'X'};
  ICF_EXPECT_OK(store::write_file_atomic(options.path, bad_magic));
  store::WalRecovery ignored;
  ICF_EXPECT_OUTCOME(Outcome::Corrupt,
                     store::Wal::open(options, [](const store::RecordHeader&, std::span<const std::byte>) {
                       return Status::ok();
                     }, ignored));

  std::vector<std::byte> bad_version = original.value();
  bad_version[8] = std::byte{0};
  bad_version[9] = std::byte{99};
  const std::uint32_t crc = crc32c(std::span<const std::byte>(bad_version.data(), 56));
  bad_version[56] = static_cast<std::byte>((crc >> 24) & 0xFFu);
  bad_version[57] = static_cast<std::byte>((crc >> 16) & 0xFFu);
  bad_version[58] = static_cast<std::byte>((crc >> 8) & 0xFFu);
  bad_version[59] = static_cast<std::byte>(crc & 0xFFu);
  ICF_EXPECT_OK(store::write_file_atomic(options.path, bad_version));
  store::WalRecovery ignored_again;
  ICF_EXPECT_OUTCOME(Outcome::Incompatible,
                     store::Wal::open(options, [](const store::RecordHeader&, std::span<const std::byte>) {
                       return Status::ok();
                     }, ignored_again));

  // A replayed log (sequence numbers that do not increase) is refused outright.
  ICF_EXPECT_OK(store::write_file_atomic(options.path, original.value()));
  {
    Result<store::Wal> wal = store::Wal::open(options, [](const store::RecordHeader&, std::span<const std::byte>) {
      return Status::ok();
    }, recovery);
    ICF_ASSERT_OK(wal.status());
    ICF_EXPECT_OK(wal.value().append(store::RecordKind::Mutation, Sequence(1), Timestamp::from_unix_nanos(1),
                                     payload_of("first")));
    ICF_EXPECT_OK(wal.value().append(store::RecordKind::Mutation, Sequence(2), Timestamp::from_unix_nanos(1),
                                     payload_of("second")));
  }
  Result<std::vector<std::byte>> two = store::read_file_bounded(options.path, 1 << 20);
  ICF_ASSERT_OK(two.status());
  std::vector<std::byte> replayed = two.value();
  // Rewrite the first record's sequence to 5, making the second record's sequence regress.
  replayed[store::kWalHeaderSize + 8] = std::byte{0};
  replayed[store::kWalHeaderSize + 15] = std::byte{5};
  const std::uint32_t header_crc =
      crc32c(std::span<const std::byte>(replayed.data() + store::kWalHeaderSize, 28));
  replayed[store::kWalHeaderSize + 28] = static_cast<std::byte>((header_crc >> 24) & 0xFFu);
  replayed[store::kWalHeaderSize + 29] = static_cast<std::byte>((header_crc >> 16) & 0xFFu);
  replayed[store::kWalHeaderSize + 30] = static_cast<std::byte>((header_crc >> 8) & 0xFFu);
  replayed[store::kWalHeaderSize + 31] = static_cast<std::byte>(header_crc & 0xFFu);
  const std::size_t first_record_size =
      store::kRecordHeaderSize + 5 + store::kRecordTrailerSize;
  const std::uint32_t record_crc =
      crc32c(std::span<const std::byte>(replayed.data() + store::kWalHeaderSize, store::kRecordHeaderSize + 5));
  replayed[store::kWalHeaderSize + store::kRecordHeaderSize + 5] =
      static_cast<std::byte>((record_crc >> 24) & 0xFFu);
  replayed[store::kWalHeaderSize + store::kRecordHeaderSize + 6] =
      static_cast<std::byte>((record_crc >> 16) & 0xFFu);
  replayed[store::kWalHeaderSize + store::kRecordHeaderSize + 7] =
      static_cast<std::byte>((record_crc >> 8) & 0xFFu);
  replayed[store::kWalHeaderSize + store::kRecordHeaderSize + 8] = static_cast<std::byte>(record_crc & 0xFFu);
  (void)first_record_size;
  ICF_EXPECT_OK(store::write_file_atomic(options.path, replayed));
  store::WalRecovery replay_recovery;
  ICF_EXPECT_OUTCOME(Outcome::Replayed,
                     store::Wal::open(options, [](const store::RecordHeader&, std::span<const std::byte>) {
                       return Status::ok();
                     }, replay_recovery));
}

ICF_TEST(wal, bounds_are_enforced_on_append) {
  TempDir directory("wal-bounds");
  store::WalOptions options;
  options.path = directory.child("test.wal");
  options.max_bytes = store::kWalHeaderSize + 4096;
  options.max_records = 4;
  store::WalRecovery recovery;
  Result<store::Wal> wal = store::Wal::open(options, [](const store::RecordHeader&, std::span<const std::byte>) {
    return Status::ok();
  }, recovery);
  ICF_ASSERT_OK(wal.status());
  for (int index = 0; index < 4; ++index) {
    ICF_EXPECT_OK(wal.value().append(store::RecordKind::Mutation, Sequence(static_cast<std::uint64_t>(index + 1)),
                                     Timestamp::from_unix_nanos(1), payload_of("x")));
  }
  ICF_EXPECT_OUTCOME(Outcome::CapacityExceeded,
                     wal.value().append(store::RecordKind::Mutation, Sequence(5), Timestamp::from_unix_nanos(1),
                                        payload_of("x")));
  ICF_EXPECT_TRUE(wal.value().needs_compaction(0, 4));
}

ICF_TEST(snapshot, round_trip_and_integrity) {
  TempDir directory("snapshot");
  Rng rng(41);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  store::StoreMeta meta;
  meta.term = Term(6);
  meta.incarnation = IncarnationId::random(rng);
  meta.revision = Revision(3);
  meta.sequence = Sequence(9);
  meta.written_at = Timestamp::from_unix_nanos(1234);
  meta.truncations = 2;

  Result<std::vector<std::byte>> encoded = store::encode_snapshot(meta, fixture.registry);
  ICF_ASSERT_OK(encoded.status());
  Result<store::Snapshot> decoded = store::decode_snapshot(encoded.value());
  ICF_ASSERT_OK(decoded.status());
  ICF_EXPECT_EQ(fixture.registry.digest(), decoded.value().registry.digest());
  ICF_EXPECT_EQ(6ull, decoded.value().meta.term.value());
  ICF_EXPECT_EQ(9ull, decoded.value().meta.sequence.value());
  ICF_EXPECT_EQ(2ull, decoded.value().meta.truncations);

  std::vector<std::byte> truncated = encoded.value();
  truncated.resize(truncated.size() - 1);
  ICF_EXPECT_OUTCOME(Outcome::Incomplete, store::decode_snapshot(truncated));

  std::vector<std::byte> corrupted = encoded.value();
  corrupted[store::kSnapshotHeaderSize + 3] =
      static_cast<std::byte>(std::to_integer<std::uint8_t>(corrupted[store::kSnapshotHeaderSize + 3]) ^ 0xFFu);
  ICF_EXPECT_OUTCOME(Outcome::Corrupt, store::decode_snapshot(corrupted));

  std::vector<std::byte> bad_version = encoded.value();
  bad_version[8] = std::byte{0};
  bad_version[9] = std::byte{9};
  const std::uint32_t header_crc = crc32c(std::span<const std::byte>(bad_version.data(), 20));
  bad_version[20] = static_cast<std::byte>((header_crc >> 24) & 0xFFu);
  bad_version[21] = static_cast<std::byte>((header_crc >> 16) & 0xFFu);
  bad_version[22] = static_cast<std::byte>((header_crc >> 8) & 0xFFu);
  bad_version[23] = static_cast<std::byte>(header_crc & 0xFFu);
  ICF_EXPECT_OUTCOME(Outcome::Incompatible, store::decode_snapshot(bad_version));

  // A snapshot whose recorded state digest disagrees with its contents is refused.
  std::vector<std::byte> mismatched = encoded.value();
  mismatched[80] = static_cast<std::byte>(std::to_integer<std::uint8_t>(mismatched[80]) ^ 0x01u);
  ICF_EXPECT_OUTCOME(Outcome::Corrupt, store::decode_snapshot(mismatched));
}

ICF_TEST(durable_store, recovery_replays_mutations_and_meta) {
  TempDir directory("store-recovery");
  Rng rng(42);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  store::DurableStore::Options options;
  options.directory = directory.path();
  options.snapshot_name = "test.snapshot";
  options.wal_name = "test.wal";

  Sequence last_sequence;
  {
    store::DurableStore::Recovery recovery;
    Result<store::DurableStore> store = store::DurableStore::open(options, recovery);
    ICF_ASSERT_OK(store.status());
    ICF_EXPECT_TRUE(recovery.created_fresh);
    store::Mutation mutation;
    mutation.kind = store::MutationKind::ClusterPut;
    mutation.cluster = fixture.source.cluster;
    ICF_ASSERT_OK(store.value().append(mutation, Timestamp::from_unix_nanos(1)).status());
    mutation.cluster = fixture.target.cluster;
    ICF_ASSERT_OK(store.value().append(mutation, Timestamp::from_unix_nanos(2)).status());
    mutation.kind = store::MutationKind::ContractPut;
    // A grant refers to a contract, so the contract has to be in the log first.
    model::ContractRecord contract;
    contract.id = ContractId::parse("11111111-2222-4333-8444-555555555555").value();
    contract.parties[0] = model::PartyRef{fixture.source.cluster.id, fixture.source.endpoint,
                                          fixture.source.cluster.domain};
    contract.parties[1] = model::PartyRef{fixture.target.cluster.id, fixture.target.endpoint,
                                          fixture.target.cluster.domain};
    contract.capacity = CapacityUnits(10);
    contract.lease_duration = Duration::from_seconds(60);
    contract.created_at = Timestamp::from_unix_nanos(1);
    mutation.contract = contract;
    ICF_ASSERT_OK(store.value().append(mutation, Timestamp::from_unix_nanos(3)));
    mutation.kind = store::MutationKind::GrantPut;
    model::GrantRecord grant;
    grant.id = GrantId::parse("11111111-2222-4333-8444-666666666666").value();
    grant.contract = contract.id;
    grant.attempt = AttemptId::parse("11111111-2222-4333-8444-777777777777").value();
    grant.issued_at = Timestamp::from_unix_nanos(1);
    grant.valid_until = Timestamp::from_unix_nanos(1000);
    grant.state = model::GrantState::Active;
    mutation.grant = grant;
    Result<Sequence> appended = store.value().append(mutation, Timestamp::from_unix_nanos(4));
    ICF_ASSERT_OK(appended.status());
    last_sequence = appended.value();
    store::StoreMeta meta;
    meta.term = Term(11);
    meta.incarnation = IncarnationId::random(rng);
    ICF_ASSERT_OK(store.value().append_meta(meta, Timestamp::from_unix_nanos(4)).status());
  }

  store::DurableStore::Recovery recovery;
  Result<store::DurableStore> reopened = store::DurableStore::open(options, recovery);
  ICF_ASSERT_OK(reopened.status());
  ICF_EXPECT_TRUE(recovery.recovered_from_store);
  ICF_EXPECT_FALSE(recovery.created_fresh);
  ICF_EXPECT_EQ(static_cast<std::size_t>(2), recovery.registry.clusters().size());
  ICF_EXPECT_EQ(static_cast<std::size_t>(1), recovery.registry.grants().size());
  ICF_EXPECT_TRUE(recovery.registry.find_grant(GrantId::parse("11111111-2222-4333-8444-666666666666").value()) !=
                  nullptr);
  ICF_EXPECT_EQ(11ull, recovery.meta.term.value());
  ICF_EXPECT_TRUE(recovery.wal.last_sequence.value() > last_sequence.value());
  ICF_EXPECT_OK(recovery.registry.validate());
}

ICF_TEST(durable_store, compaction_then_reopen) {
  TempDir directory("store-compaction");
  Rng rng(43);
  PairFixture fixture = make_authorized_pair(rng);
  store::DurableStore::Options options;
  options.directory = directory.path();
  options.snapshot_name = "compact.snapshot";
  options.wal_name = "compact.wal";

  store::DurableStore::Recovery recovery;
  Result<store::DurableStore> store = store::DurableStore::open(options, recovery);
  ICF_ASSERT_OK(store.status());
  model::Registry registry;
  ICF_ASSERT_OK(registry.put_cluster(fixture.source.cluster));
  store::Mutation mutation;
  mutation.kind = store::MutationKind::ClusterPut;
  mutation.cluster = fixture.source.cluster;
  ICF_ASSERT_OK(store.value().append(mutation, Timestamp::from_unix_nanos(1)).status());
  ICF_EXPECT_TRUE(store.value().wal_records() > 0);
  store::StoreMeta meta;
  meta.term = Term(4);
  meta.incarnation = IncarnationId::random(rng);
  ICF_ASSERT_OK(store.value().compact(registry, meta, Timestamp::from_unix_nanos(2)));
  ICF_EXPECT_EQ(0ull, store.value().wal_records());
  ICF_EXPECT_TRUE(store::file_exists(directory.child("compact.snapshot")));

  store::DurableStore::Recovery second;
  Result<store::DurableStore> reopened = store::DurableStore::open(options, second);
  ICF_ASSERT_OK(reopened.status());
  ICF_EXPECT_TRUE(second.snapshot_loaded);
  ICF_EXPECT_EQ(static_cast<std::size_t>(1), second.registry.clusters().size());
  ICF_EXPECT_EQ(4ull, second.meta.term.value());
}

ICF_TEST(durable_store, refuses_a_corrupt_snapshot) {
  TempDir directory("store-corrupt-snapshot");
  Rng rng(44);
  PairFixture fixture = make_authorized_pair(rng);
  store::DurableStore::Options options;
  options.directory = directory.path();
  options.snapshot_name = "corrupt.snapshot";
  options.wal_name = "corrupt.wal";
  store::DurableStore::Recovery recovery;
  Result<store::DurableStore> store = store::DurableStore::open(options, recovery);
  ICF_ASSERT_OK(store.status());
  model::Registry registry;
  ICF_ASSERT_OK(registry.put_cluster(fixture.source.cluster));
  ICF_ASSERT_OK(store.value().compact(registry, store::StoreMeta{}, Timestamp::from_unix_nanos(1)));

  Result<std::vector<std::byte>> bytes = store::read_file_bounded(directory.child("corrupt.snapshot"), 1 << 20);
  ICF_ASSERT_OK(bytes.status());
  std::vector<std::byte> damaged = bytes.value();
  damaged[store::kSnapshotHeaderSize + 1] =
      static_cast<std::byte>(std::to_integer<std::uint8_t>(damaged[store::kSnapshotHeaderSize + 1]) ^ 0xFFu);
  ICF_EXPECT_OK(store::write_file_atomic(directory.child("corrupt.snapshot"), damaged));

  store::DurableStore::Recovery second;
  ICF_EXPECT_OUTCOME(Outcome::Corrupt, store::DurableStore::open(options, second));
}

ICF_TEST(durable_store, mutation_validation_rejects_inconsistent_state) {
  model::Registry registry;
  Rng rng(45);
  PairFixture fixture = make_authorized_pair(rng);
  ICF_ASSERT_OK(registry.put_cluster(fixture.source.cluster));

  store::Mutation dangling_reservation;
  dangling_reservation.kind = store::MutationKind::ReservationPut;
  dangling_reservation.reservation.id = ReservationId::random(rng);
  dangling_reservation.reservation.grant = GrantId::random(rng);
  ICF_EXPECT_OUTCOME(Outcome::Invalid, store::validate_mutation(registry, dangling_reservation));

  store::Mutation unknown_kind;
  unknown_kind.kind = static_cast<store::MutationKind>(777);
  ICF_EXPECT_OUTCOME(Outcome::Invalid, store::validate_mutation(registry, unknown_kind));

  store::Mutation link_without_endpoints;
  link_without_endpoints.kind = store::MutationKind::LinkPut;
  link_without_endpoints.link.id = EdgeId::parse("edge").value();
  ICF_EXPECT_OUTCOME(Outcome::Invalid, store::validate_mutation(registry, link_without_endpoints));
}
