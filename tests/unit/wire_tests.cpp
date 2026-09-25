#include <string>
#include <vector>

#include "harness.hpp"
#include "icf/wire/frame.hpp"
#include "icf/wire/messages.hpp"
#include "model_builder.hpp"

using namespace icf;
using namespace icf::test;

namespace {

std::vector<std::byte> make_frame(wire::MessageType type, const std::vector<std::byte>& payload,
                                 std::span<const std::byte> key = {}) {
  std::vector<std::byte> out;
  wire::FrameHeader header;
  header.version = limits::kProtocolVersionMax;
  header.type = type;
  header.flags = key.empty() ? 0u : wire::kFlagSigned;
  const Status status = wire::append_frame(out, header, payload, key);
  (void)status;
  return out;
}

}  // namespace

ICF_TEST(wire, frame_round_trip) {
  const std::vector<std::byte> payload{std::byte{1}, std::byte{2}, std::byte{3}};
  const std::vector<std::byte> bytes = make_frame(wire::MessageType::Ping, payload);
  wire::FrameParser parser;
  ICF_EXPECT_OK(parser.push(bytes));
  Result<std::optional<wire::Frame>> frame = parser.next({});
  ICF_ASSERT_TRUE(frame.has_value());
  ICF_ASSERT_TRUE(frame.value().has_value());
  ICF_EXPECT_EQ(wire::MessageType::Ping, frame.value().value().header.type);
  ICF_EXPECT_EQ(payload.size(), frame.value().value().payload.size());
  ICF_EXPECT_EQ(std::byte{2}, frame.value().value().payload[1]);
  ICF_EXPECT_TRUE(parser.buffered() == 0);
}

ICF_TEST(wire, partial_delivery_is_buffered) {
  const std::vector<std::byte> payload(500, std::byte{7});
  const std::vector<std::byte> bytes = make_frame(wire::MessageType::Query, payload);
  wire::FrameParser parser;
  std::size_t offset = 0;
  constexpr std::size_t kChunk = 7;
  while (offset < bytes.size()) {
    const std::size_t take = std::min(kChunk, bytes.size() - offset);
    ICF_EXPECT_OK(parser.push(std::span<const std::byte>(bytes.data() + offset, take)));
    offset += take;
    Result<std::optional<wire::Frame>> frame = parser.next({});
    ICF_ASSERT_TRUE(frame.has_value());
    if (offset < bytes.size()) {
      ICF_EXPECT_FALSE(frame.value().has_value());
    } else {
      ICF_ASSERT_TRUE(frame.value().has_value());
      ICF_EXPECT_EQ(payload.size(), frame.value().value().payload.size());
    }
  }
}

ICF_TEST(wire, rejects_malformed_headers) {
  const std::vector<std::byte> payload{std::byte{9}};
  std::vector<std::byte> bytes = make_frame(wire::MessageType::Ping, payload);

  std::vector<std::byte> bad_magic = bytes;
  bad_magic[0] = std::byte{'X'};
  wire::FrameParser magic_parser;
  ICF_EXPECT_OK(magic_parser.push(bad_magic));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, magic_parser.next({}));

  std::vector<std::byte> bad_version = bytes;
  bad_version[4] = std::byte{0x00};
  bad_version[5] = std::byte{0x63};
  bad_version[16] = std::byte{0};
  bad_version[17] = std::byte{0};
  bad_version[18] = std::byte{0};
  bad_version[19] = std::byte{0};
  // Recompute the header CRC so that the version check is the one that fires.
  const std::uint32_t crc = crc32c(std::span<const std::byte>(bad_version.data(), 16));
  bad_version[16] = static_cast<std::byte>((crc >> 24) & 0xFFu);
  bad_version[17] = static_cast<std::byte>((crc >> 16) & 0xFFu);
  bad_version[18] = static_cast<std::byte>((crc >> 8) & 0xFFu);
  bad_version[19] = static_cast<std::byte>(crc & 0xFFu);
  wire::FrameParser version_parser;
  ICF_EXPECT_OK(version_parser.push(bad_version));
  ICF_EXPECT_OUTCOME(Outcome::Incompatible, version_parser.next({}));

  std::vector<std::byte> bad_crc = bytes;
  bad_crc[17] = static_cast<std::byte>(std::to_integer<std::uint8_t>(bad_crc[17]) ^ 0x01u);
  wire::FrameParser crc_parser;
  ICF_EXPECT_OK(crc_parser.push(bad_crc));
  ICF_EXPECT_OUTCOME(Outcome::Corrupt, crc_parser.next({}));

  std::vector<std::byte> bad_payload = bytes;
  bad_payload.back() = static_cast<std::byte>(std::to_integer<std::uint8_t>(bad_payload.back()) ^ 0xFFu);
  wire::FrameParser payload_parser;
  ICF_EXPECT_OK(payload_parser.push(bad_payload));
  ICF_EXPECT_OUTCOME(Outcome::Corrupt, payload_parser.next({}));

  std::vector<std::byte> bad_type = bytes;
  bad_type[6] = std::byte{0xFF};
  bad_type[7] = std::byte{0xFF};
  const std::uint32_t type_crc = crc32c(std::span<const std::byte>(bad_type.data(), 16));
  bad_type[16] = static_cast<std::byte>((type_crc >> 24) & 0xFFu);
  bad_type[17] = static_cast<std::byte>((type_crc >> 16) & 0xFFu);
  bad_type[18] = static_cast<std::byte>((type_crc >> 8) & 0xFFu);
  bad_type[19] = static_cast<std::byte>(type_crc & 0xFFu);
  wire::FrameParser type_parser;
  ICF_EXPECT_OK(type_parser.push(bad_type));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, type_parser.next({}));
}

ICF_TEST(wire, rejects_oversized_declared_length_before_allocating) {
  std::vector<std::byte> header(limits::kFrameHeaderSize, std::byte{0});
  header[0] = std::byte{'I'};
  header[1] = std::byte{'C'};
  header[2] = std::byte{'F'};
  header[3] = std::byte{'1'};
  header[4] = std::byte{0};
  header[5] = std::byte{1};
  header[6] = std::byte{0};
  header[7] = std::byte{1};
  const std::uint32_t declared = 0xFFFFFFF0u;
  header[12] = static_cast<std::byte>((declared >> 24) & 0xFFu);
  header[13] = static_cast<std::byte>((declared >> 16) & 0xFFu);
  header[14] = static_cast<std::byte>((declared >> 8) & 0xFFu);
  header[15] = static_cast<std::byte>(declared & 0xFFu);
  const std::uint32_t crc = crc32c(std::span<const std::byte>(header.data(), 16));
  header[16] = static_cast<std::byte>((crc >> 24) & 0xFFu);
  header[17] = static_cast<std::byte>((crc >> 16) & 0xFFu);
  header[18] = static_cast<std::byte>((crc >> 8) & 0xFFu);
  header[19] = static_cast<std::byte>(crc & 0xFFu);
  wire::FrameParser parser;
  ICF_EXPECT_OK(parser.push(header));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, parser.next({}));

  wire::FrameParser bounded(1024);
  ICF_EXPECT_OUTCOME(Outcome::Invalid, bounded.push(std::vector<std::byte>(4096, std::byte{0})));
}

ICF_TEST(wire, signed_frames_verify_and_tampering_is_rejected) {
  const std::string key_text = "shared-channel-key";
  const std::span<const std::byte> key(reinterpret_cast<const std::byte*>(key_text.data()), key_text.size());
  const std::vector<std::byte> payload{std::byte{4}, std::byte{5}, std::byte{6}};
  const std::vector<std::byte> bytes = make_frame(wire::MessageType::Query, payload, key);
  wire::FrameParser parser;
  ICF_EXPECT_OK(parser.push(bytes));
  Result<std::optional<wire::Frame>> frame = parser.next(key);
  ICF_ASSERT_TRUE(frame.has_value());
  ICF_ASSERT_TRUE(frame.value().has_value());
  ICF_EXPECT_TRUE(frame.value().value().signed_frame);

  std::vector<std::byte> tampered = bytes;
  tampered[limits::kFrameHeaderSize] = static_cast<std::byte>(std::to_integer<std::uint8_t>(tampered[limits::kFrameHeaderSize]) ^ 0x01u);
  // Fix up both CRCs so the MAC is the only thing that can fail.
  const std::uint32_t payload_crc = crc32c(std::span<const std::byte>(tampered.data() + limits::kFrameHeaderSize, payload.size()));
  tampered[limits::kFrameHeaderSize + payload.size()] = static_cast<std::byte>((payload_crc >> 24) & 0xFFu);
  tampered[limits::kFrameHeaderSize + payload.size() + 1] = static_cast<std::byte>((payload_crc >> 16) & 0xFFu);
  tampered[limits::kFrameHeaderSize + payload.size() + 2] = static_cast<std::byte>((payload_crc >> 8) & 0xFFu);
  tampered[limits::kFrameHeaderSize + payload.size() + 3] = static_cast<std::byte>(payload_crc & 0xFFu);
  wire::FrameParser tampered_parser;
  ICF_EXPECT_OK(tampered_parser.push(tampered));
  ICF_EXPECT_OUTCOME(Outcome::Unauthorized, tampered_parser.next(key));

  // A signed frame on an unsigned channel, and vice versa, are both refused.
  wire::FrameParser unsigned_channel;
  ICF_EXPECT_OK(unsigned_channel.push(bytes));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, unsigned_channel.next({}));
  wire::FrameParser signed_channel;
  ICF_EXPECT_OK(signed_channel.push(make_frame(wire::MessageType::Ping, payload)));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, signed_channel.next(key));
}

ICF_TEST(wire, hello_round_trip) {
  Rng rng(31);
  wire::HelloMessage hello;
  hello.role = wire::PeerRole::Agent;
  hello.cluster = ClusterId::parse("cluster-a").value();
  hello.domain = AuthorityDomainId::parse("domain-north").value();
  hello.incarnation = IncarnationId::random(rng);
  hello.generation = Generation(42);
  hello.policy_generation = PolicyGeneration(7);
  hello.agent_term = Term(9);
  hello.capabilities = wire::kCapabilityAll;
  hello.content_digest = Sha256::hash(std::string_view("content"));
  hello.started_at = Timestamp::from_unix_nanos(1234567);

  Result<std::vector<std::byte>> payload = wire::encode_message(hello);
  ICF_ASSERT_TRUE(payload.has_value());
  ByteReader reader(payload.value());
  Result<wire::HelloMessage> decoded = wire::decode_hello(reader);
  ICF_ASSERT_TRUE(decoded.has_value());
  ICF_EXPECT_OK(reader.expect_end());
  ICF_EXPECT_EQ(hello.cluster, decoded.value().cluster);
  ICF_EXPECT_EQ(hello.incarnation, decoded.value().incarnation);
  ICF_EXPECT_EQ(hello.generation, decoded.value().generation);
  ICF_EXPECT_EQ(hello.content_digest, decoded.value().content_digest);
  ICF_EXPECT_EQ(hello.started_at.unix_nanos(), decoded.value().started_at.unix_nanos());
}

ICF_TEST(wire, every_message_round_trips) {
  Rng rng(32);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  const SessionToken session = SessionToken::random(rng);
  const Uuid request = Uuid::random(rng);

  {
    wire::HelloAckMessage message;
    message.session = session;
    message.coordinator = IncarnationId::random(rng);
    message.coordinator_term = Term(3);
    message.outcome = Outcome::Ok;
    message.negotiated_version = 1;
    message.view_digest = fixture.registry.digest();
    message.revalidate = {fixture.grant};
    message.detail = "detail";
    Result<std::vector<std::byte>> payload = wire::encode_message(message);
    ICF_ASSERT_TRUE(payload.has_value());
    ByteReader reader(payload.value());
    Result<wire::HelloAckMessage> decoded = wire::decode_hello_ack(reader);
    ICF_ASSERT_TRUE(decoded.has_value());
    ICF_EXPECT_OK(reader.expect_end());
    ICF_EXPECT_EQ(message.session, decoded.value().session);
    ICF_EXPECT_EQ(1u, static_cast<unsigned>(decoded.value().revalidate.size()));
  }
  {
    wire::ReportClusterMessage message;
    message.session = session;
    message.cluster = fixture.source.cluster;
    Result<std::vector<std::byte>> payload = wire::encode_message(message);
    ICF_ASSERT_TRUE(payload.has_value());
    ByteReader reader(payload.value());
    Result<wire::ReportClusterMessage> decoded = wire::decode_report_cluster(reader);
    ICF_ASSERT_TRUE(decoded.has_value());
    ICF_EXPECT_OK(reader.expect_end());
    ICF_EXPECT_EQ(message.cluster.id, decoded.value().cluster.id);
    ICF_EXPECT_EQ(message.cluster.endpoints.size(), decoded.value().cluster.endpoints.size());
  }
  {
    wire::PrepareGrantMessage message;
    message.session = session;
    message.grant = *fixture.registry.find_grant(fixture.grant);
    Result<std::vector<std::byte>> payload = wire::encode_message(message);
    ICF_ASSERT_TRUE(payload.has_value());
    ByteReader reader(payload.value());
    Result<wire::PrepareGrantMessage> decoded = wire::decode_prepare_grant(reader);
    ICF_ASSERT_TRUE(decoded.has_value());
    ICF_EXPECT_OK(reader.expect_end());
    ICF_EXPECT_EQ(message.grant.id, decoded.value().grant.id);
    ICF_EXPECT_EQ(message.grant.attempt, decoded.value().grant.attempt);
  }
  {
    wire::FenceMessage message;
    message.session = session;
    message.coordinator_term = Term(4);
    message.grants = {fixture.grant};
    message.reason = "reincarnation";
    Result<std::vector<std::byte>> payload = wire::encode_message(message);
    ICF_ASSERT_TRUE(payload.has_value());
    ByteReader reader(payload.value());
    Result<wire::FenceMessage> decoded = wire::decode_fence(reader);
    ICF_ASSERT_TRUE(decoded.has_value());
    ICF_EXPECT_OK(reader.expect_end());
    ICF_EXPECT_EQ(static_cast<std::size_t>(1), decoded.value().grants.size());
  }
  {
    wire::StatusReportMessage message;
    message.session = session;
    message.request = request;
    message.cluster = fixture.source.cluster.id;
    message.incarnation = fixture.source.cluster.incarnation;
    message.generation = fixture.source.cluster.generation;
    message.policy_generation = fixture.source.cluster.policy_generation;
    message.agent_term = Term(5);
    wire::GrantStatusEntry entry;
    entry.grant = fixture.grant;
    entry.attempt = AttemptId::random(rng);
    entry.state = model::GrantState::Active;
    entry.agent_term = Term(5);
    message.grants.push_back(entry);
    Result<std::vector<std::byte>> payload = wire::encode_message(message);
    ICF_ASSERT_TRUE(payload.has_value());
    ByteReader reader(payload.value());
    Result<wire::StatusReportMessage> decoded = wire::decode_status_report(reader);
    ICF_ASSERT_TRUE(decoded.has_value());
    ICF_EXPECT_OK(reader.expect_end());
    ICF_EXPECT_EQ(model::GrantState::Active, decoded.value().grants.front().state);
  }
  {
    wire::QueryMessage message;
    message.request = request;
    message.kind = wire::QueryKind::Decide;
    message.endpoint = fixture.source.endpoint;
    message.endpoint_b = fixture.target.endpoint;
    message.capacity = CapacityUnits(10);
    message.limit = 32;
    message.expect_source_generation = true;
    message.source_generation = Generation(5);
    Result<std::vector<std::byte>> payload = wire::encode_message(message);
    ICF_ASSERT_TRUE(payload.has_value());
    ByteReader reader(payload.value());
    Result<wire::QueryMessage> decoded = wire::decode_query(reader);
    ICF_ASSERT_TRUE(decoded.has_value());
    ICF_EXPECT_OK(reader.expect_end());
    ICF_EXPECT_EQ(message.kind, decoded.value().kind);
    ICF_EXPECT_EQ(message.endpoint, decoded.value().endpoint);
    ICF_EXPECT_TRUE(decoded.value().expect_source_generation);
  }
  {
    wire::QueryResultMessage message;
    message.request = request;
    message.kind = wire::QueryKind::Decide;
    message.outcome = Outcome::DegradedAuthorized;
    model::Decision decision;
    decision.outcome = Outcome::DegradedAuthorized;
    decision.reasons = {model::ReasonCode::PathDegraded};
    decision.paths = {PathId::parse("path-ab").value()};
    decision.degraded = true;
    decision.detail = "degraded";
    message.decision = decision;
    Result<std::vector<std::byte>> payload = wire::encode_message(message);
    ICF_ASSERT_TRUE(payload.has_value());
    ByteReader reader(payload.value());
    Result<wire::QueryResultMessage> decoded = wire::decode_query_result(reader);
    ICF_ASSERT_TRUE(decoded.has_value());
    ICF_EXPECT_OK(reader.expect_end());
    ICF_ASSERT_TRUE(decoded.value().decision.has_value());
    ICF_EXPECT_EQ(Outcome::DegradedAuthorized, decoded.value().decision->outcome);
    ICF_EXPECT_TRUE(decoded.value().decision->degraded);
  }
  {
    wire::AdminMessage message;
    message.request = request;
    message.action = wire::AdminAction::UpsertLink;
    message.link = *fixture.registry.find_link(EdgeId::parse("edge-ab").value());
    message.cluster_id = fixture.source.cluster.id;
    message.cluster_b = fixture.target.cluster.id;
    message.endpoint = fixture.source.endpoint;
    message.endpoint_b = fixture.target.endpoint;
    message.generation = Generation(3);
    message.link_state = model::LinkState::Degraded;
    message.capacity = CapacityUnits(7);
    message.lease_duration = Duration::from_seconds(30);
    message.reason = "reason";
    Result<std::vector<std::byte>> payload = wire::encode_message(message);
    ICF_ASSERT_TRUE(payload.has_value());
    ByteReader reader(payload.value());
    Result<wire::AdminMessage> decoded = wire::decode_admin(reader);
    ICF_ASSERT_TRUE(decoded.has_value());
    ICF_EXPECT_OK(reader.expect_end());
    ICF_ASSERT_TRUE(decoded.value().link.has_value());
    ICF_EXPECT_EQ(message.link->id, decoded.value().link->id);
    ICF_EXPECT_EQ(message.lease_duration.nanos(), decoded.value().lease_duration.nanos());
  }
  {
    wire::WithdrawMessage message;
    message.session = session;
    message.cluster = fixture.source.cluster.id;
    message.incarnation = fixture.source.cluster.incarnation;
    message.generation = fixture.source.cluster.generation;
    message.reason = "operator";
    Result<std::vector<std::byte>> payload = wire::encode_message(message);
    ICF_ASSERT_TRUE(payload.has_value());
    ByteReader reader(payload.value());
    Result<wire::WithdrawMessage> decoded = wire::decode_withdraw(reader);
    ICF_ASSERT_TRUE(decoded.has_value());
    ICF_EXPECT_OK(reader.expect_end());
    ICF_EXPECT_EQ(message.cluster, decoded.value().cluster);
  }
  {
    wire::ErrorMessage message;
    message.request = request;
    message.outcome = Outcome::Indeterminate;
    message.detail = "ambiguous";
    Result<std::vector<std::byte>> payload = wire::encode_message(message);
    ICF_ASSERT_TRUE(payload.has_value());
    ByteReader reader(payload.value());
    Result<wire::ErrorMessage> decoded = wire::decode_error(reader);
    ICF_ASSERT_TRUE(decoded.has_value());
    ICF_EXPECT_OK(reader.expect_end());
    ICF_EXPECT_EQ(Outcome::Indeterminate, decoded.value().outcome);
  }
}

ICF_TEST(wire, truncated_message_payloads_are_refused) {
  Rng rng(33);
  wire::HelloMessage hello;
  hello.cluster = ClusterId::parse("cluster-a").value();
  hello.domain = AuthorityDomainId::parse("domain").value();
  hello.incarnation = IncarnationId::random(rng);
  hello.role = wire::PeerRole::Agent;
  Result<std::vector<std::byte>> payload = wire::encode_message(hello);
  ICF_ASSERT_TRUE(payload.has_value());
  for (std::size_t cut = 1; cut < payload.value().size(); cut += 3) {
    ByteReader reader(std::span<const std::byte>(payload.value().data(), payload.value().size() - cut));
    const Result<wire::HelloMessage> decoded = wire::decode_hello(reader);
    // A truncated message either fails to decode or leaves trailing bytes; both are refusals.
    ICF_EXPECT_TRUE(!decoded.has_value() || !reader.expect_end().is_ok());
  }
  // Trailing bytes are refused: a message must match its schema exactly.
  std::vector<std::byte> extended = payload.value();
  extended.push_back(std::byte{0});
  ByteReader reader(extended);
  // The schema is exact: trailing bytes are refused by the decoder itself.
  ICF_EXPECT_OUTCOME(Outcome::Invalid, wire::decode_hello(reader));
}

ICF_TEST(wire, enum_bounds_are_enforced) {
  // A role value outside the enumeration must be refused before anything else uses it.
  std::vector<std::byte> payload;
  ByteWriter writer;
  writer.u8(9);  // invalid peer role
  payload = writer.data();
  ByteReader reader(payload);
  ICF_EXPECT_OUTCOME(Outcome::Invalid, wire::decode_hello(reader));

  // A grant state outside the enumeration is refused.
  ByteWriter grant_writer;
  ByteWriter body;
  const std::vector<std::byte> grant_payload = []() {
    Rng rng(34);
    model::GrantRecord grant;
    grant.id = GrantId::random(rng);
    grant.contract = ContractId::random(rng);
    grant.attempt = AttemptId::random(rng);
    grant.state = model::GrantState::Active;
    ByteWriter writer;
    model::encode_grant(grant, writer);
    return writer.data();
  }();
  std::vector<std::byte> tampered = grant_payload;
  // state field: id(16) + contract(16) + digest(32) + term(8) + coordinator(16) + attempt(16) + 2*(16+8+8) +
  // capacity(8) + issued(8) + valid_until(8) = 176 bytes before the state byte.
  const std::size_t state_offset = 16 + 16 + 32 + 8 + 16 + 16 + 2 * (16 + 8 + 8) + 8 + 8 + 8;
  ICF_ASSERT_TRUE(state_offset < tampered.size());
  tampered[state_offset] = std::byte{200};
  ByteReader tampered_reader(tampered);
  ICF_EXPECT_OUTCOME(Outcome::Invalid, model::decode_grant(tampered_reader));
}
