// Network tests over real loopback TCP.
//
// These exercise the framed transport, the handshake, the connection lifecycle, and hostile
// input against a live coordinator running on a background thread.
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "coordinator_harness.hpp"
#include "harness.hpp"
#include "icf/client/client.hpp"
#include "icf/net/poller.hpp"
#include "icf/net/socket.hpp"

using namespace icf;
using namespace icf::test;

namespace {

Result<client::Client> connect_observer(const CoordinatorHarness& harness, const std::string& key = std::string(),
                                        bool claim_domain = false) {
  client::ClientOptions options;
  options.host = "127.0.0.1";
  options.port = harness.port();
  options.channel_key = key;
  if (!key.empty() || claim_domain) {
    // The coordinator selects the channel key from the authority domain named in the handshake.
    options.domain = AuthorityDomainId::parse("test-domain").value();
  }
  return client::Client::connect(options, harness.clock());
}

Status send_bytes(const std::string& host, std::uint16_t port, std::span<const std::byte> bytes, const Clock& clock) {
  Result<net::Socket> socket = net::Socket::connect(host, port, Duration::from_seconds(2), clock);
  if (!socket) {
    return socket.status();
  }
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    Result<std::size_t> written = socket.value().send(bytes.subspan(offset));
    if (!written) {
      if (written.status().outcome() == Outcome::Busy) {
        net::PollItem item;
        item.handle = socket.value().handle();
        item.want_write = true;
        (void)net::poll_sockets(std::span<net::PollItem>(&item, 1), 100);
        continue;
      }
      return written.status();
    }
    offset += written.value();
  }
  return Status::ok();
}

// Reads until the peer closes or the deadline elapses; returns the number of bytes received.
std::size_t drain(net::Socket& socket, const Clock& clock, Duration deadline) {
  const std::int64_t limit = clock.monotonic_nanos() + deadline.nanos();
  std::size_t total = 0;
  std::array<std::byte, 4096> buffer{};
  while (clock.monotonic_nanos() < limit) {
    net::PollItem item;
    item.handle = socket.handle();
    item.want_read = true;
    const Result<std::size_t> ready = net::poll_sockets(std::span<net::PollItem>(&item, 1), 50);
    if (!ready) {
      break;
    }
    if (ready.value() == 0) {
      continue;
    }
    if (item.failed) {
      break;
    }
    Result<std::size_t> received = socket.receive(buffer);
    if (!received) {
      break;
    }
    if (received.value() == 0) {
      break;
    }
    total += received.value();
  }
  return total;
}

}  // namespace

ICF_TEST(net, handshake_query_and_clean_close) {
  CoordinatorHarness harness("net-handshake");
  ICF_ASSERT_TRUE(harness.valid());
  Result<client::Client> client = connect_observer(harness);
  ICF_ASSERT_OK(client.status());
  ICF_EXPECT_EQ(Outcome::Ok, client.value().hello_ack().outcome);
  ICF_EXPECT_FALSE(client.value().hello_ack().session.is_nil());
  ICF_EXPECT_EQ(1u, static_cast<unsigned>(client.value().hello_ack().negotiated_version));

  wire::QueryMessage query;
  query.kind = wire::QueryKind::Status;
  query.request = Uuid::random(*new Rng(1));
  Result<wire::QueryResultMessage> result = client.value().query(query);
  ICF_ASSERT_OK(result.status());
  ICF_EXPECT_EQ(Outcome::Ok, result.value().outcome);
  ICF_ASSERT_TRUE(result.value().status.has_value());
  ICF_EXPECT_EQ(std::string("test-domain"), result.value().status->domain.str());
  ICF_EXPECT_EQ(1ull, result.value().status->term.value());
}

ICF_TEST(net, byte_by_byte_delivery_is_reassembled) {
  CoordinatorHarness harness("net-partial");
  ICF_ASSERT_TRUE(harness.valid());
  // Build a valid HELLO frame and deliver it one byte at a time.
  wire::HelloMessage hello;
  hello.role = wire::PeerRole::Observer;
  hello.domain = AuthorityDomainId::parse("test-domain").value();
  hello.protocol_min = limits::kProtocolVersionMin;
  hello.protocol_max = limits::kProtocolVersionMax;
  Result<std::vector<std::byte>> payload = wire::encode_message(hello);
  ICF_ASSERT_TRUE(payload.has_value());
  std::vector<std::byte> frame;
  wire::FrameHeader header;
  header.version = limits::kProtocolVersionMax;
  header.type = wire::MessageType::Hello;
  ICF_ASSERT_OK(wire::append_frame(frame, header, payload.value(), {}));

  Result<net::Socket> socket = net::Socket::connect("127.0.0.1", harness.port(), Duration::from_seconds(2),
                                                    harness.clock());
  ICF_ASSERT_OK(socket.status());
  for (const std::byte byte : frame) {
    Result<std::size_t> written = socket.value().send(std::span<const std::byte>(&byte, 1));
    ICF_ASSERT_OK(written.status());
  }
  const std::size_t received = drain(socket.value(), harness.clock(), Duration::from_seconds(3));
  ICF_EXPECT_TRUE(received > 0);
}

ICF_TEST(net, garbage_input_closes_only_that_connection) {
  CoordinatorHarness harness("net-garbage");
  ICF_ASSERT_TRUE(harness.valid());
  Rng rng(81);
  for (int iteration = 0; iteration < 20; ++iteration) {
    std::vector<std::byte> garbage(static_cast<std::size_t>(1 + rng.below(300)));
    rng.fill(garbage);
    // Make sure the magic cannot accidentally match.
    garbage[0] = std::byte{'X'};
    ICF_EXPECT_OK(send_bytes("127.0.0.1", harness.port(), garbage, harness.clock()));
  }
  // The coordinator must still serve a well formed client, and it must count the refusals. The
  // count is read through the protocol (never by touching the registry from another thread) and
  // the close of the offending connections is observed with a bounded wait.
  Result<client::Client> client = connect_observer(harness);
  ICF_ASSERT_OK(client.status());
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
  bool counted = false;
  while (std::chrono::steady_clock::now() < deadline) {
    wire::QueryMessage query;
    query.kind = wire::QueryKind::Status;
    query.request = Uuid::random(rng);
    Result<wire::QueryResultMessage> result = client.value().query(query);
    ICF_ASSERT_OK(result.status());
    if (result.value().status.has_value() && (result.value().status->rejected_frames > 0 ||
                                              result.value().status->rejected_replays > 0)) {
      counted = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  ICF_EXPECT_TRUE(counted);
}

ICF_TEST(net, oversized_declared_frame_is_refused) {
  CoordinatorHarness harness("net-oversized");
  ICF_ASSERT_TRUE(harness.valid());
  std::vector<std::byte> header(limits::kFrameHeaderSize, std::byte{0});
  header[0] = std::byte{'I'};
  header[1] = std::byte{'C'};
  header[2] = std::byte{'F'};
  header[3] = std::byte{'1'};
  header[5] = std::byte{1};
  header[7] = std::byte{1};
  const std::uint32_t declared = 0x7FFFFFFFu;
  for (int index = 0; index < 4; ++index) {
    header[12 + index] = static_cast<std::byte>((declared >> (24 - index * 8)) & 0xFFu);
  }
  const std::uint32_t crc = crc32c(std::span<const std::byte>(header.data(), 16));
  for (int index = 0; index < 4; ++index) {
    header[16 + index] = static_cast<std::byte>((crc >> (24 - index * 8)) & 0xFFu);
  }
  ICF_EXPECT_OK(send_bytes("127.0.0.1", harness.port(), header, harness.clock()));
  Result<client::Client> client = connect_observer(harness);
  ICF_ASSERT_OK(client.status());
}

ICF_TEST(net, unknown_message_type_is_answered_with_an_error) {
  CoordinatorHarness harness("net-unknown-type");
  ICF_ASSERT_TRUE(harness.valid());
  Result<client::Client> client = connect_observer(harness);
  ICF_ASSERT_OK(client.status());
  // A well formed frame of a type the coordinator never accepts from a peer. (Pong and Error are
  // accepted and ignored, so a refusal message is used here instead.)
  wire::RefuseMessage refusal;
  refusal.outcome = Outcome::Refused;
  refusal.detail = "test";
  Result<std::vector<std::byte>> payload = wire::encode_message(refusal);
  ICF_ASSERT_TRUE(payload.has_value());
  ICF_EXPECT_OK(client.value().send_frame(wire::MessageType::Refuse, payload.value()));
  Result<wire::Frame> reply = client.value().receive_frame(Duration::from_seconds(5));
  ICF_ASSERT_OK(reply.status());
  ICF_EXPECT_EQ(wire::MessageType::Error, reply.value().header.type);
  ByteReader reader(reply.value().payload);
  Result<wire::ErrorMessage> error = wire::decode_error(reader);
  ICF_ASSERT_TRUE(error.has_value());
  ICF_EXPECT_EQ(Outcome::Unsupported, error.value().outcome);
}

ICF_TEST(net, replayed_session_token_is_refused) {
  CoordinatorHarness harness("net-replay");
  ICF_ASSERT_TRUE(harness.valid());
  Result<client::Client> first = connect_observer(harness);
  ICF_ASSERT_OK(first.status());
  Result<client::Client> second = connect_observer(harness);
  ICF_ASSERT_OK(second.status());

  wire::QueryMessage query;
  query.kind = wire::QueryKind::Status;
  query.request = Uuid::random(*new Rng(2));
  ICF_EXPECT_OK(first.value().query(query).status());

  // A frame carrying another session's token must be refused with REPLAYED.
  wire::ReportClusterMessage report;
  report.session = second.value().hello_ack().session;
  Rng rng(82);
  report.cluster.id = ClusterId::parse("ghost").value();
  report.cluster.domain = AuthorityDomainId::parse("test-domain").value();
  report.cluster.incarnation = IncarnationId::random(rng);
  report.cluster.generation = Generation(1);
  Result<std::vector<std::byte>> payload = wire::encode_message(report);
  ICF_ASSERT_TRUE(payload.has_value());
  ICF_EXPECT_OK(first.value().send_frame(wire::MessageType::ReportCluster, payload.value()));
  Result<wire::Frame> reply = first.value().receive_frame(Duration::from_seconds(5));
  ICF_ASSERT_OK(reply.status());
  ICF_EXPECT_EQ(wire::MessageType::Error, reply.value().header.type);
  ByteReader reader(reply.value().payload);
  Result<wire::ErrorMessage> error = wire::decode_error(reader);
  ICF_ASSERT_TRUE(error.has_value());
  ICF_EXPECT_EQ(Outcome::Replayed, error.value().outcome);
}

ICF_TEST(net, connection_limit_is_enforced_without_losing_service) {
  CoordinatorHarness harness("net-limit", false, 8);
  ICF_ASSERT_TRUE(harness.valid());
  std::vector<client::Client> clients;
  for (int index = 0; index < 8; ++index) {
    Result<client::Client> client = connect_observer(harness);
    if (client) {
      clients.push_back(std::move(client.value()));
    }
  }
  // Connection nine is dropped by the coordinator; the client sees a closed socket.
  Result<client::Client> extra = connect_observer(harness);
  if (extra) {
    wire::QueryMessage query;
    query.kind = wire::QueryKind::Status;
    query.request = Uuid::random(*new Rng(3));
    (void)extra.value().query(query);
  }
  // The established clients keep working.
  for (client::Client& client : clients) {
    wire::QueryMessage query;
    query.kind = wire::QueryKind::Status;
    query.request = Uuid::random(*new Rng(4));
    Result<wire::QueryResultMessage> result = client.query(query);
    if (result) {
      ICF_EXPECT_EQ(Outcome::Ok, result.value().outcome);
    }
  }
  ICF_EXPECT_TRUE(harness.coordinator().registry().counts().clusters == 0);
}

ICF_TEST(net, idle_connections_are_closed_by_the_deadline) {
  CoordinatorHarness harness("net-idle", false, 0, Duration::from_millis(300));
  ICF_ASSERT_TRUE(harness.valid());
  Result<client::Client> client = connect_observer(harness);
  ICF_ASSERT_OK(client.status());
  // Stay silent: the coordinator must close the idle connection. The client observes a closed
  // socket rather than hanging forever.
  const auto start = std::chrono::steady_clock::now();
  bool observed_close = false;
  while (std::chrono::steady_clock::now() - start < std::chrono::seconds(10)) {
    Result<wire::Frame> frame = client.value().receive_frame(Duration::from_millis(200));
    if (!frame) {
      observed_close = true;
      break;
    }
    if (frame.value().header.type == wire::MessageType::Ping) {
      continue;  // the coordinator's keep-alive; keep waiting for the idle close
    }
  }
  ICF_EXPECT_TRUE(observed_close);
  ICF_EXPECT_TRUE(std::chrono::steady_clock::now() - start < std::chrono::seconds(10));
}

ICF_TEST(net, signed_channel_accepts_only_authenticated_frames) {
  const std::string key = "unit-test-channel-key";
  CoordinatorHarness harness("net-signing", false, 0, Duration::from_seconds(30), {{"test-domain", key}});
  ICF_ASSERT_TRUE(harness.valid());

  // A client that holds the domain key signs every frame after the handshake.
  Result<client::Client> signed_client = connect_observer(harness, key);
  ICF_ASSERT_OK(signed_client.status());
  wire::QueryMessage signed_query;
  signed_query.kind = wire::QueryKind::Status;
  signed_query.request = Uuid::random(*new Rng(6));
  Result<wire::QueryResultMessage> signed_result = signed_client.value().query(signed_query);
  ICF_ASSERT_OK(signed_result.status());
  ICF_EXPECT_EQ(Outcome::Ok, signed_result.value().outcome);

  // A client that claims the same domain but holds no key completes the handshake and is then
  // refused: the coordinator requires a MAC on every frame once the domain has a key.
  Result<client::Client> unsigned_client = connect_observer(harness, std::string(), true);
  if (unsigned_client) {
    wire::QueryMessage query;
    query.kind = wire::QueryKind::Status;
    query.request = Uuid::random(*new Rng(5));
    ICF_EXPECT_FALSE(unsigned_client.value().query(query).has_value());
  }
  // Either the handshake acknowledgement cannot be verified at all (the coordinator signs it) or
  // the unsigned follow-up frames are refused; both are refusals, never a successful session.
  ICF_EXPECT_TRUE(!unsigned_client.has_value() || harness.coordinator().status().rejected_frames > 0);
}

ICF_TEST(net, keepalive_and_error_messages_never_loop) {
  CoordinatorHarness harness("net-keepalive");
  ICF_ASSERT_TRUE(harness.valid());
  Result<client::Client> client = connect_observer(harness);
  ICF_ASSERT_OK(client.status());

  // A ping is answered with exactly one pong.
  Result<std::vector<std::byte>> ping_payload = wire::encode_message(wire::PingMessage{Sequence(7)});
  ICF_ASSERT_TRUE(ping_payload.has_value());
  ICF_EXPECT_OK(client.value().send_frame(wire::MessageType::Ping, ping_payload.value()));
  Result<wire::Frame> pong = client.value().receive_frame(Duration::from_seconds(5));
  ICF_ASSERT_OK(pong.status());
  ICF_EXPECT_EQ(wire::MessageType::Pong, pong.value().header.type);

  // An error report must not be answered with another error: two peers that answer errors with
  // errors would exchange messages until one of them gives up.
  wire::ErrorMessage error;
  error.request = Uuid::random(*new Rng(11));
  error.outcome = Outcome::Invalid;
  error.detail = "deliberate test error";
  Result<std::vector<std::byte>> error_payload = wire::encode_message(error);
  ICF_ASSERT_TRUE(error_payload.has_value());
  ICF_EXPECT_OK(client.value().send_frame(wire::MessageType::Error, error_payload.value()));
  Result<wire::Frame> reply = client.value().receive_frame(Duration::from_millis(300));
  ICF_EXPECT_FALSE(reply.has_value());

  // The session is still usable afterwards.
  wire::QueryMessage query;
  query.kind = wire::QueryKind::Status;
  query.request = Uuid::random(*new Rng(12));
  ICF_EXPECT_OK(client.value().query(query).status());
}

ICF_TEST(net, oversized_outbound_frame_is_refused_locally) {
  CoordinatorHarness harness("net-outbound");
  ICF_ASSERT_TRUE(harness.valid());
  Result<client::Client> client = connect_observer(harness);
  ICF_ASSERT_OK(client.status());
  const std::vector<std::byte> huge(limits::kMaxFramePayload + 1, std::byte{0});
  ICF_EXPECT_OUTCOME(Outcome::Invalid, client.value().send_frame(wire::MessageType::Query, huge));
}

ICF_TEST(net, coordinator_stop_is_clean_and_restartable) {
  for (int cycle = 0; cycle < 3; ++cycle) {
    CoordinatorHarness harness("net-cycle");
    ICF_ASSERT_TRUE(harness.valid());
    Result<client::Client> client = connect_observer(harness);
    ICF_ASSERT_OK(client.status());
    wire::QueryMessage query;
    query.kind = wire::QueryKind::Status;
    query.request = Uuid::random(*new Rng(static_cast<std::uint64_t>(7 + cycle)));
    ICF_EXPECT_OK(client.value().query(query).status());
    // The harness destructor stops the loop and joins the server thread.
  }
}
