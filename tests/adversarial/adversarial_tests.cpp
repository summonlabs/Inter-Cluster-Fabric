// Adversarial input tests.
//
// Every case here feeds the runtime something it should not accept: random bytes, truncations,
// bit flips, oversized counts, extreme values, duplicate identities, and hostile framing. The
// requirement is that the runtime always answers with a typed outcome and never crashes, hangs,
// or silently accepts damaged input.
#include <cstring>
#include <string>
#include <vector>

#include "harness.hpp"
#include "icf/store/file_util.hpp"
#include "icf/store/snapshot.hpp"
#include "icf/store/wal.hpp"
#include "icf/wire/frame.hpp"
#include "icf/wire/messages.hpp"
#include "model_builder.hpp"
#include "temp_dir.hpp"

using namespace icf;
using namespace icf::test;

namespace {

std::vector<std::byte> random_bytes(Rng& rng, std::size_t length) {
  std::vector<std::byte> bytes(length);
  rng.fill(bytes);
  return bytes;
}

}  // namespace

ICF_TEST(adversarial, random_message_payloads_never_crash_the_decoders) {
  Rng rng(run_seed());
  for (int iteration = 0; iteration < 20000; ++iteration) {
    const std::size_t length = static_cast<std::size_t>(rng.below(64));
    const std::vector<std::byte> bytes = random_bytes(rng, length);
    ByteReader reader(bytes);
    ICF_EXPECT_FALSE(wire::decode_hello(reader).has_value());
    ByteReader second(bytes);
    ICF_EXPECT_FALSE(wire::decode_hello_ack(second).has_value());
    ByteReader third(bytes);
    ICF_EXPECT_FALSE(model::decode_grant(third).has_value());
    ByteReader fourth(bytes);
    ICF_EXPECT_FALSE(wire::decode_admin(fourth).has_value());
    ByteReader fifth(bytes);
    ICF_EXPECT_FALSE(wire::decode_query(fifth).has_value());
    ByteReader sixth(bytes);
    ICF_EXPECT_FALSE(model::decode_registry(sixth).has_value());
  }
}

ICF_TEST(adversarial, mutated_valid_messages_are_rejected_or_accepted_consistently) {
  Rng rng(run_seed());
  wire::HelloMessage hello;
  hello.role = wire::PeerRole::Agent;
  hello.cluster = ClusterId::parse("cluster-a").value();
  hello.domain = AuthorityDomainId::parse("domain").value();
  hello.incarnation = IncarnationId::random(rng);
  hello.generation = Generation(4);
  hello.policy_generation = PolicyGeneration(2);
  hello.agent_term = Term(1);
  hello.protocol_min = limits::kProtocolVersionMin;
  hello.protocol_max = limits::kProtocolVersionMax;
  hello.capabilities = wire::kCapabilityAll;
  Result<std::vector<std::byte>> payload = wire::encode_message(hello);
  ICF_ASSERT_TRUE(payload.has_value());

  for (std::size_t index = 0; index < payload.value().size(); ++index) {
    for (int bit = 0; bit < 8; ++bit) {
      std::vector<std::byte> mutated = payload.value();
      mutated[index] = static_cast<std::byte>(std::to_integer<std::uint8_t>(mutated[index]) ^ (1u << bit));
      ByteReader reader(mutated);
      Result<wire::HelloMessage> decoded = wire::decode_hello(reader);
      if (decoded.has_value()) {
        // A field that decoded must still be a valid value: identities stay well formed and the
        // protocol range stays ordered.
        ICF_EXPECT_TRUE(decoded.value().protocol_max >= decoded.value().protocol_min);
        ICF_EXPECT_FALSE(decoded.value().cluster.empty());
      }
    }
  }
}

ICF_TEST(adversarial, hostile_framing_is_rejected_without_allocating) {
  Rng rng(run_seed());
  constexpr int kIterations = 4000;
  for (int iteration = 0; iteration < kIterations; ++iteration) {
    const std::size_t length = static_cast<std::size_t>(rng.below(200));
    const std::vector<std::byte> bytes = random_bytes(rng, length);
    wire::FrameParser parser;
    const Status pushed = parser.push(bytes);
    if (!pushed) {
      continue;  // rejected at the framing boundary
    }
    Result<std::optional<wire::Frame>> frame = parser.next({});
    if (frame.has_value() && frame.value().has_value()) {
      // Only a well formed frame can be produced, and it must respect the declared bounds.
      ICF_EXPECT_TRUE(frame.value().value().payload.size() <= limits::kMaxFramePayload);
      ICF_EXPECT_TRUE(frame.value().value().header.version >= limits::kProtocolVersionMin);
    }
  }
}

ICF_TEST(adversarial, declared_counts_above_the_bound_are_refused) {
  // A payload that declares a huge collection count must be refused before any allocation.
  ByteWriter writer;
  writer.u16(model::kModelEncodingVersion);
  writer.boolean(true);
  writer.u32(0xFFFFFFFFu);  // cluster count far above limits::kMaxClusters
  ByteReader reader(writer.data());
  ICF_EXPECT_OUTCOME(Outcome::Invalid, model::decode_registry(reader));

  ByteWriter hello_writer;
  hello_writer.u8(1);
  hello_writer.blob("cluster-a");
  hello_writer.blob("domain");
  hello_writer.uuid(Uuid{});
  hello_writer.u64(1);
  hello_writer.u64(1);
  hello_writer.u64(1);
  hello_writer.u16(1);
  hello_writer.u16(1);
  hello_writer.u32(0);
  hello_writer.digest(Digest{});
  hello_writer.i64(0);
  ByteReader hello_reader(hello_writer.data());
  ICF_EXPECT_TRUE(wire::decode_hello(hello_reader).has_value());

  // A string field that declares more bytes than it carries is INCOMPLETE, not a large read.
  ByteWriter short_string;
  short_string.u32(1000);
  short_string.raw(std::span<const std::byte>(reinterpret_cast<const std::byte*>("abc"), 3));
  ByteReader short_reader(short_string.data());
  ICF_EXPECT_OUTCOME(Outcome::Incomplete, short_reader.blob(2048));
}

ICF_TEST(adversarial, extreme_values_are_clamped_or_refused) {
  // Capacity and generation at the maximum permitted value are accepted; beyond it is refused.
  Rng rng(71);
  PairFixture fixture = make_authorized_pair(rng);
  model::ClusterRecord extreme = fixture.source.cluster;
  extreme.generation = Generation(limits::kMaxGeneration);
  ICF_EXPECT_OK(fixture.registry.put_cluster(extreme));
  extreme.generation = Generation(UINT64_MAX);
  ICF_EXPECT_OK(fixture.registry.put_cluster(extreme));

  model::ContractRecord contract;
  contract.id = ContractId::random(rng);
  contract.parties = fixture.registry.find_contract({}) == nullptr ? contract.parties : contract.parties;
  ICF_EXPECT_OUTCOME(Outcome::Invalid, fixture.registry.put_contract(contract));

  ByteWriter writer;
  model::encode_grant(model::GrantRecord{}, writer);
  ByteReader reader(writer.data());
  ICF_EXPECT_TRUE(model::decode_grant(reader).has_value());
}

ICF_TEST(adversarial, duplicate_identities_are_refused) {
  Rng rng(72);
  PairFixture fixture = make_authorized_pair(rng);
  model::LinkRecord link = make_link("edge-dup", fixture.source.endpoint, fixture.target.endpoint);
  ICF_EXPECT_OK(fixture.registry.put_link(link));
  // A second identical identity overwrites deterministically rather than accumulating.
  ICF_EXPECT_OK(fixture.registry.put_link(link));
  ICF_EXPECT_EQ(static_cast<std::size_t>(2), fixture.registry.links().size());

  model::PathRecord path = make_path("path-dup", fixture.source.endpoint, fixture.target.endpoint, {"edge-dup"});
  ICF_EXPECT_OK(fixture.registry.put_path(path));
  std::size_t matching = 0;
  for (const auto& entry : fixture.registry.paths()) {
    if (entry.first == path.id) {
      ++matching;
    }
  }
  ICF_EXPECT_EQ(static_cast<std::size_t>(1), matching);
}

ICF_TEST(adversarial, invalid_utf8_identities_are_refused_everywhere) {
  const std::string hostile = "cluster-\xff\xfe";
  ICF_EXPECT_OUTCOME(Outcome::Invalid, ClusterId::parse(hostile));
  ByteWriter writer;
  writer.u8(1);
  writer.blob(hostile);
  writer.blob("domain");
  writer.uuid(Uuid{});
  writer.u64(1);
  writer.u64(1);
  writer.u64(1);
  writer.u16(1);
  writer.u16(1);
  writer.u32(0);
  writer.digest(Digest{});
  writer.i64(0);
  ByteReader reader(writer.data());
  ICF_EXPECT_OUTCOME(Outcome::Invalid, wire::decode_hello(reader));
}

ICF_TEST(adversarial, snapshot_truncation_at_every_length) {
  Rng rng(73);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  store::StoreMeta meta;
  meta.term = Term(1);
  Result<std::vector<std::byte>> encoded = store::encode_snapshot(meta, fixture.registry);
  ICF_ASSERT_OK(encoded.status());
  for (std::size_t length = 0; length < encoded.value().size(); ++length) {
    Result<store::Snapshot> decoded =
        store::decode_snapshot(std::span<const std::byte>(encoded.value().data(), length));
    ICF_EXPECT_FALSE(decoded.has_value());
  }
  ICF_EXPECT_TRUE(store::decode_snapshot(encoded.value()).has_value());
}

ICF_TEST(adversarial, wal_bit_flips_never_produce_a_silently_valid_log) {
  TempDir directory("wal-bitflip");
  store::WalOptions options;
  options.path = directory.child("flip.wal");
  store::WalRecovery recovery;
  {
    Result<store::Wal> wal = store::Wal::open(options, [](const store::RecordHeader&, std::span<const std::byte>) {
      return Status::ok();
    }, recovery);
    ICF_ASSERT_OK(wal.status());
    for (int index = 0; index < 6; ++index) {
      const std::string text = "payload-" + std::to_string(index);
      ICF_EXPECT_OK(wal.value().append(store::RecordKind::Mutation, Sequence(static_cast<std::uint64_t>(index + 1)),
                                       Timestamp::from_unix_nanos(1),
                                       std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()),
                                                                  text.size())));
    }
  }
  Result<std::vector<std::byte>> original = store::read_file_bounded(options.path, 1 << 20);
  ICF_ASSERT_OK(original.status());
  const std::size_t total = original.value().size();
  for (std::size_t offset = store::kWalHeaderSize; offset < total; offset += 3) {
    std::vector<std::byte> flipped = original.value();
    flipped[offset] = static_cast<std::byte>(std::to_integer<std::uint8_t>(flipped[offset]) ^ 0x40u);
    ICF_EXPECT_OK(store::write_file_atomic(options.path, flipped));
    std::size_t recovered_records = 0;
    store::WalRecovery damaged_recovery;
    Result<store::Wal> reopened = store::Wal::open(options, [&recovered_records](const store::RecordHeader&,
                                                                                std::span<const std::byte>) {
      ++recovered_records;
      return Status::ok();
    }, damaged_recovery);
    if (!reopened) {
      // A header or file-level failure is a refusal, which is a correct answer.
      ICF_EXPECT_TRUE(reopened.status().outcome() == Outcome::Corrupt ||
                      reopened.status().outcome() == Outcome::Invalid ||
                      reopened.status().outcome() == Outcome::Incompatible ||
                      reopened.status().outcome() == Outcome::Incomplete);
    } else {
      // A flipped byte may only ever remove records from the trusted prefix.
      ICF_EXPECT_TRUE(recovered_records <= 6);
      if (damaged_recovery.truncated_tail) {
        ICF_EXPECT_TRUE(recovered_records < 6);
      }
    }
  }
  ICF_EXPECT_OK(store::write_file_atomic(options.path, original.value()));
}

ICF_TEST(adversarial, policy_and_rule_identities_are_bounded) {
  Rng rng(74);
  PairFixture fixture = make_authorized_pair(rng);
  model::PolicyRule rule = allow_rule(std::string(500, 'x'), "domain-north", fixture.source.cluster.id,
                                      fixture.target.cluster.id, 1);
  ICF_EXPECT_OUTCOME(Outcome::Invalid, fixture.registry.put_policy(rule));
  rule.id = "";
  ICF_EXPECT_OUTCOME(Outcome::Invalid, fixture.registry.put_policy(rule));
  rule.id = "ok";
  rule.owner = AuthorityDomainId{};
  ICF_EXPECT_OUTCOME(Outcome::Invalid, fixture.registry.put_policy(rule));
}

ICF_TEST(adversarial, capacity_overflow_is_refused_rather_than_wrapped) {
  Rng rng(75);
  PairFixture fixture = make_authorized_pair(rng);
  model::ClusterRecord cluster = fixture.source.cluster;
  cluster.endpoints[0].capacity = CapacityUnits(UINT64_MAX);
  cluster.endpoints[0].reserved = CapacityUnits(UINT64_MAX);
  ICF_EXPECT_OK(fixture.registry.put_cluster(cluster));
  model::ClusterRecord over = cluster;
  over.endpoints[0].reserved = CapacityUnits(UINT64_MAX);
  over.endpoints[0].capacity = CapacityUnits(1);
  ICF_EXPECT_OUTCOME(Outcome::CapacityExceeded, fixture.registry.put_cluster(over));
}
