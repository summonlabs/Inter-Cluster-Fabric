// Coordinator state-machine tests.
//
// The first group drives a coordinator without sockets: every message is handed to
// handle_message() under a made-up connection identity, exactly as the event loop would hand it
// over, and the result is read from the registry. The second group talks to a live coordinator
// over loopback TCP in the role of the cluster agents, to observe what the coordinator sends them.
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "coordinator_harness.hpp"
#include "harness.hpp"
#include "icf/client/client.hpp"
#include "icf/runtime/agent.hpp"
#include "icf/runtime/coordinator.hpp"
#include "icf/store/durable_store.hpp"
#include "model_builder.hpp"
#include "temp_dir.hpp"

using namespace icf;
using namespace icf::test;

namespace {

template <class Message>
wire::Frame frame_of(wire::MessageType type, const Message& message) {
  Result<std::vector<std::byte>> payload = wire::encode_message(message);
  if (!payload) {
    ICF_FAIL("a test message could not be encoded: " + payload.status().to_string());
  }
  wire::Frame frame;
  frame.header.version = limits::kProtocolVersionMax;
  frame.header.type = type;
  frame.header.payload_length = static_cast<std::uint32_t>(payload.value().size());
  frame.payload = std::move(payload.value());
  return frame;
}

// One cluster agent as the coordinator sees it: a connection, an identity, and a session.
struct Party {
  std::uint64_t connection = 0;
  ClusterId cluster;
  AuthorityDomainId domain;
  EndpointId endpoint;
  IncarnationId incarnation;
  Generation generation{1};
  SessionToken token;
};

// A coordinator that is driven message by message, with no event loop running.
class Bench {
 public:
  explicit Bench(const std::string& name)
      : directory_(name), clock_(Timestamp::from_unix_nanos(1700000000000000000)) {
    started_ = start();
  }

  [[nodiscard]] const Status& started() const noexcept { return started_; }
  [[nodiscard]] runtime::Coordinator& coordinator() { return *coordinator_; }
  [[nodiscard]] const model::Registry& registry() const { return coordinator_->registry(); }
  [[nodiscard]] ManualClock& clock() noexcept { return clock_; }

  // Stops the coordinator and starts a new one over the same state directory.
  [[nodiscard]] Status restart() {
    coordinator_.reset();
    started_ = start();
    return started_;
  }

  void hello(Party& party) {
    wire::HelloMessage message;
    message.role = wire::PeerRole::Agent;
    message.cluster = party.cluster;
    message.domain = party.domain;
    message.incarnation = party.incarnation;
    message.generation = party.generation;
    message.policy_generation = PolicyGeneration(1);
    message.agent_term = Term(1);
    message.protocol_min = limits::kProtocolVersionMin;
    message.protocol_max = limits::kProtocolVersionMax;
    message.capabilities = wire::kCapabilityAll;
    ICF_ASSERT_OK(coordinator().handle_message(party.connection, frame_of(wire::MessageType::Hello, message)));
    const auto session = coordinator().sessions().find(party.connection);
    ICF_ASSERT_TRUE(session != coordinator().sessions().end());
    party.token = session->second.token;
  }

  void report(const Party& party, std::uint64_t capacity) {
    wire::ReportClusterMessage message;
    message.session = party.token;
    message.cluster.id = party.cluster;
    message.cluster.domain = party.domain;
    message.cluster.incarnation = party.incarnation;
    message.cluster.generation = party.generation;
    message.cluster.policy_generation = PolicyGeneration(1);
    message.cluster.state = model::ClusterState::Active;
    message.cluster.endpoints.push_back(
        endpoint_for(party.cluster, party.endpoint.str(), "/" + party.endpoint.str(), capacity, PolicyGeneration(1)));
    ICF_ASSERT_OK(coordinator().handle_message(party.connection, frame_of(wire::MessageType::ReportCluster, message)));
  }

  Party join(std::uint64_t connection, const std::string& cluster, const std::string& domain,
             const std::string& endpoint, std::uint64_t capacity) {
    Party party;
    party.connection = connection;
    party.cluster = ClusterId::parse(cluster).value();
    party.domain = AuthorityDomainId::parse(domain).value();
    party.endpoint = EndpointId::parse(endpoint).value();
    party.incarnation = IncarnationId::random(rng_);
    hello(party);
    report(party, capacity);
    return party;
  }

  void consent(const Party& party, const ContractId& contract) {
    const model::ContractRecord* record = registry().find_contract(contract);
    ICF_ASSERT_TRUE(record != nullptr);
    wire::ContractConsentMessage message;
    message.session = party.token;
    message.contract = contract;
    message.terms_digest = record->terms_digest;
    message.decision = model::ConsentDecision::Accepted;
    message.endpoint = party.endpoint;
    message.incarnation = party.incarnation;
    message.generation = party.generation;
    message.policy_generation = PolicyGeneration(1);
    message.agent_term = Term(1);
    message.reason = "accepted";
    ICF_ASSERT_OK(
        coordinator().handle_message(party.connection, frame_of(wire::MessageType::ContractConsent, message)));
  }

  ContractId contract(const Party& a, const Party& b, std::uint64_t capacity) {
    wire::AdminMessage request;
    request.action = wire::AdminAction::AuthorizeContract;
    request.cluster_id = a.cluster;
    request.endpoint = a.endpoint;
    request.cluster_b = b.cluster;
    request.endpoint_b = b.endpoint;
    request.capacity = CapacityUnits(capacity);
    request.lease_duration = Duration::from_seconds(120);
    wire::AdminResultMessage result;
    ICF_ASSERT_OK(coordinator().handle_admin(request, result));
    consent(a, result.contract);
    consent(b, result.contract);
    return result.contract;
  }

  GrantId issue(const ContractId& contract) {
    wire::AdminMessage request;
    request.action = wire::AdminAction::IssueGrant;
    request.contract = contract;
    wire::AdminResultMessage result;
    ICF_ASSERT_OK(coordinator().handle_admin(request, result));
    return result.grant;
  }

  [[nodiscard]] AttemptId attempt_of(const GrantId& grant) const {
    const model::GrantRecord* record = registry().find_grant(grant);
    return record == nullptr ? AttemptId{} : record->attempt;
  }

  [[nodiscard]] Status prepared(const Party& party, const GrantId& grant) {
    wire::GrantPreparedMessage message;
    message.session = party.token;
    message.grant = grant;
    message.attempt = attempt_of(grant);
    message.accepted = true;
    message.agent_term = Term(1);
    message.detail = "prepared";
    return coordinator().handle_message(party.connection, frame_of(wire::MessageType::GrantPrepared, message));
  }

  [[nodiscard]] Status committed(const Party& party, const GrantId& grant) {
    wire::GrantCommittedMessage message;
    message.session = party.token;
    message.grant = grant;
    message.attempt = attempt_of(grant);
    message.installed = true;
    message.agent_term = Term(1);
    message.detail = "enforced";
    return coordinator().handle_message(party.connection, frame_of(wire::MessageType::GrantCommitted, message));
  }

  [[nodiscard]] Status aborted(const Party& party, const GrantId& grant, const AttemptId& attempt) {
    wire::GrantAbortedMessage message;
    message.session = party.token;
    message.grant = grant;
    message.attempt = attempt;
    message.reason = "abandoned by the cluster agent";
    return coordinator().handle_message(party.connection, frame_of(wire::MessageType::GrantAborted, message));
  }

  // Issues a grant and takes it through prepare and commit on both sides.
  GrantId commit(const Party& a, const Party& b, const ContractId& contract) {
    const GrantId grant = issue(contract);
    ICF_ASSERT_OK(prepared(a, grant));
    ICF_ASSERT_OK(prepared(b, grant));
    ICF_ASSERT_OK(committed(a, grant));
    ICF_ASSERT_OK(committed(b, grant));
    return grant;
  }

  [[nodiscard]] model::GrantState state_of(const GrantId& grant) const {
    const model::GrantRecord* record = registry().find_grant(grant);
    if (record == nullptr) {
      ICF_FAIL("the grant is not registered");
    }
    return record->state;
  }

  [[nodiscard]] std::uint64_t reserved_on(const Party& party) const {
    const model::ClusterRecord* cluster = registry().find_cluster(party.cluster);
    if (cluster == nullptr || cluster->endpoints.empty()) {
      ICF_FAIL("the cluster has no endpoint scope");
    }
    return cluster->endpoints.front().reserved.value();
  }

  [[nodiscard]] std::size_t open_reservations() const {
    std::size_t open = 0;
    for (const auto& entry : registry().reservations()) {
      if (!entry.second.released) {
        ++open;
      }
    }
    return open;
  }

 private:
  [[nodiscard]] Status start() {
    runtime::Coordinator::Config config;
    config.state_directory = directory_.path();
    config.domain = AuthorityDomainId::parse("test-domain").value();
    config.durable = false;
    Result<std::unique_ptr<runtime::Coordinator>> created = runtime::Coordinator::create(config, clock_);
    if (!created) {
      return created.status();
    }
    coordinator_ = std::move(created.value());
    return Status::ok();
  }

  TempDir directory_;
  ManualClock clock_;
  std::unique_ptr<runtime::Coordinator> coordinator_;
  Status started_ = Status::ok();
  Rng rng_{91};
};

bool is(model::GrantState actual, model::GrantState expected) { return actual == expected; }

}  // namespace

ICF_TEST(coordinator, a_commit_acknowledgement_never_revives_a_fenced_grant) {
  Bench bench("coord-late-ack");
  ICF_ASSERT_OK(bench.started());
  const Party a = bench.join(11, "cluster-a", "domain-north", "a-scope", 100);
  const Party b = bench.join(12, "cluster-b", "domain-south", "b-scope", 100);
  const ContractId contract = bench.contract(a, b, 60);
  const GrantId grant = bench.issue(contract);
  ICF_ASSERT_OK(bench.prepared(a, grant));
  ICF_ASSERT_OK(bench.prepared(b, grant));
  ICF_ASSERT_TRUE(is(bench.state_of(grant), model::GrantState::Prepared));

  // The operator fences the grant while the commit acknowledgements are still on their way.
  wire::AdminMessage fence;
  fence.action = wire::AdminAction::FenceGrant;
  fence.grant = grant;
  wire::AdminResultMessage fenced;
  ICF_ASSERT_OK(bench.coordinator().handle_admin(fence, fenced));
  ICF_ASSERT_TRUE(is(bench.state_of(grant), model::GrantState::Fenced));

  ICF_EXPECT_OK(bench.committed(a, grant));
  ICF_EXPECT_OK(bench.committed(b, grant));
  ICF_EXPECT_TRUE(is(bench.state_of(grant), model::GrantState::Fenced));
  ICF_EXPECT_EQ(static_cast<std::size_t>(0), bench.open_reservations());
  ICF_EXPECT_EQ(0ull, bench.reserved_on(a));
  ICF_EXPECT_EQ(0ull, bench.reserved_on(b));
}

ICF_TEST(coordinator, only_a_party_abandons_a_grant_and_only_the_attempt_in_flight) {
  Bench bench("coord-abandon");
  ICF_ASSERT_OK(bench.started());
  const Party a = bench.join(11, "cluster-a", "domain-north", "a-scope", 100);
  const Party b = bench.join(12, "cluster-b", "domain-south", "b-scope", 100);
  const Party outsider = bench.join(13, "cluster-c", "domain-east", "c-scope", 100);
  const ContractId contract = bench.contract(a, b, 40);
  const GrantId committed = bench.commit(a, b, contract);
  ICF_ASSERT_TRUE(is(bench.state_of(committed), model::GrantState::Committed));
  ICF_ASSERT_TRUE(bench.reserved_on(a) == 40);

  // A session of a cluster the grant does not involve cannot end it.
  ICF_EXPECT_OK(bench.aborted(outsider, committed, bench.attempt_of(committed)));
  ICF_EXPECT_TRUE(is(bench.state_of(committed), model::GrantState::Committed));
  // A committed grant is not abandoned by a late message either: it holds reservations, and
  // ending it is the business of a fence, which releases them.
  ICF_EXPECT_OK(bench.aborted(a, committed, bench.attempt_of(committed)));
  ICF_EXPECT_TRUE(is(bench.state_of(committed), model::GrantState::Committed));
  ICF_EXPECT_EQ(40ull, bench.reserved_on(a));
  ICF_EXPECT_EQ(static_cast<std::size_t>(2), bench.open_reservations());

  // A grant that is still being prepared is abandoned by a party, for the attempt in flight only.
  const GrantId preparing = bench.issue(contract);
  ICF_ASSERT_TRUE(is(bench.state_of(preparing), model::GrantState::Preparing));
  Rng rng(92);
  ICF_EXPECT_OK(bench.aborted(a, preparing, AttemptId::random(rng)));
  ICF_EXPECT_TRUE(is(bench.state_of(preparing), model::GrantState::Preparing));
  ICF_EXPECT_OK(bench.aborted(outsider, preparing, bench.attempt_of(preparing)));
  ICF_EXPECT_TRUE(is(bench.state_of(preparing), model::GrantState::Preparing));
  ICF_EXPECT_OK(bench.aborted(a, preparing, bench.attempt_of(preparing)));
  ICF_EXPECT_TRUE(is(bench.state_of(preparing), model::GrantState::Aborted));
}

ICF_TEST(coordinator, an_older_session_closing_does_not_disturb_the_live_one) {
  Bench bench("coord-old-session");
  ICF_ASSERT_OK(bench.started());
  const Party older = bench.join(21, "cluster-a", "domain-north", "a-scope", 100);
  // The agent reconnected; the coordinator has not yet noticed that the first connection is gone.
  Party a = older;
  a.connection = 22;
  bench.hello(a);
  const Party b = bench.join(23, "cluster-b", "domain-south", "b-scope", 100);
  const ContractId contract = bench.contract(a, b, 40);
  const GrantId grant = bench.issue(contract);
  ICF_ASSERT_TRUE(is(bench.state_of(grant), model::GrantState::Preparing));

  bench.coordinator().handle_disconnect(older.connection, Status::make(Outcome::Unreachable, "closed"));
  ICF_EXPECT_TRUE(is(bench.state_of(grant), model::GrantState::Preparing));
  ICF_EXPECT_OK(bench.prepared(a, grant));
  ICF_EXPECT_OK(bench.prepared(b, grant));
  ICF_EXPECT_OK(bench.committed(a, grant));
  ICF_EXPECT_OK(bench.committed(b, grant));
  ICF_EXPECT_TRUE(is(bench.state_of(grant), model::GrantState::Committed));

  // The session the flow runs on still makes it indeterminate when it closes.
  const GrantId second = bench.issue(contract);
  bench.coordinator().handle_disconnect(a.connection, Status::make(Outcome::Unreachable, "closed"));
  ICF_EXPECT_TRUE(is(bench.state_of(second), model::GrantState::Indeterminate));
}

ICF_TEST(coordinator, a_cluster_report_keeps_the_capacity_that_is_reserved) {
  Bench bench("coord-report-reserved");
  ICF_ASSERT_OK(bench.started());
  const Party a = bench.join(11, "cluster-a", "domain-north", "a-scope", 100);
  const Party b = bench.join(12, "cluster-b", "domain-south", "b-scope", 100);
  const ContractId contract = bench.contract(a, b, 60);
  const GrantId grant = bench.commit(a, b, contract);
  ICF_ASSERT_TRUE(is(bench.state_of(grant), model::GrantState::Committed));
  ICF_ASSERT_TRUE(bench.reserved_on(a) == 60);

  // The agent reports again, as it does after every reconnect. The reservation counters are the
  // coordinator's own accounting and are not part of what the agent reports.
  bench.report(a, 100);
  bench.report(b, 100);
  ICF_EXPECT_EQ(60ull, bench.reserved_on(a));
  ICF_EXPECT_EQ(60ull, bench.reserved_on(b));

  // 60 of 100 units are held, so a second grant of 60 over the same scopes cannot be committed.
  const ContractId other = bench.contract(a, b, 60);
  const GrantId refused = bench.issue(other);
  ICF_EXPECT_OK(bench.prepared(a, refused));
  ICF_EXPECT_OK(bench.prepared(b, refused));
  (void)bench.committed(a, refused);
  (void)bench.committed(b, refused);
  ICF_EXPECT_TRUE(is(bench.state_of(refused), model::GrantState::Aborted));
  ICF_EXPECT_TRUE(is(bench.state_of(grant), model::GrantState::Committed));
  ICF_EXPECT_EQ(60ull, bench.reserved_on(a));
  ICF_EXPECT_EQ(static_cast<std::size_t>(2), bench.open_reservations());
}

ICF_TEST(coordinator, a_commit_refused_on_one_side_reserves_nothing_on_the_other) {
  Bench bench("coord-partial-reserve");
  ICF_ASSERT_OK(bench.started());
  const Party a = bench.join(11, "cluster-a", "domain-north", "a-scope", 100);
  const Party b = bench.join(12, "cluster-b", "domain-south", "b-scope", 50);
  const GrantId first = bench.commit(a, b, bench.contract(a, b, 40));
  ICF_ASSERT_TRUE(is(bench.state_of(first), model::GrantState::Committed));

  // Cluster A has room for a second grant of 40, cluster B has not.
  const GrantId second = bench.issue(bench.contract(a, b, 40));
  ICF_EXPECT_OK(bench.prepared(a, second));
  ICF_EXPECT_OK(bench.prepared(b, second));
  (void)bench.committed(a, second);
  (void)bench.committed(b, second);
  ICF_EXPECT_TRUE(is(bench.state_of(second), model::GrantState::Aborted));
  ICF_EXPECT_EQ(40ull, bench.reserved_on(a));
  ICF_EXPECT_EQ(40ull, bench.reserved_on(b));
  ICF_EXPECT_EQ(static_cast<std::size_t>(2), bench.open_reservations());
}

ICF_TEST(coordinator, a_coordinator_restarts_again_after_fencing_a_recovered_grant) {
  Bench bench("coord-restart-twice");
  ICF_ASSERT_OK(bench.started());
  const Party a = bench.join(11, "cluster-a", "domain-north", "a-scope", 100);
  const Party b = bench.join(12, "cluster-b", "domain-south", "b-scope", 100);
  const ContractId contract = bench.contract(a, b, 60);
  const GrantId grant = bench.commit(a, b, contract);
  ICF_ASSERT_TRUE(is(bench.state_of(grant), model::GrantState::Committed));

  // The first restart finds a live grant and fences it.
  ICF_ASSERT_OK(bench.restart());
  ICF_EXPECT_TRUE(is(bench.state_of(grant), model::GrantState::Fenced));
  ICF_EXPECT_EQ(static_cast<std::size_t>(0), bench.open_reservations());
  const std::size_t trail = bench.registry().audit().size();

  // The state the first restart wrote must be readable by the next one.
  ICF_ASSERT_OK(bench.restart());
  ICF_EXPECT_TRUE(is(bench.state_of(grant), model::GrantState::Fenced));
  ICF_EXPECT_TRUE(bench.registry().audit().size() > trail);
  ICF_ASSERT_OK(bench.restart());
}

ICF_TEST(coordinator, administrative_deletes_are_readable_after_a_restart) {
  Bench bench("coord-delete-restart");
  ICF_ASSERT_OK(bench.started());
  Rng rng(93);
  ClusterFixture fixture = make_cluster("cluster-x", "domain-north", "x-scope", "/x", 1, 1, rng);
  ClusterFixture peer = make_cluster("cluster-y", "domain-south", "y-scope", "/y", 1, 1, rng);
  wire::AdminResultMessage result;

  wire::AdminMessage upsert_cluster;
  upsert_cluster.action = wire::AdminAction::UpsertCluster;
  upsert_cluster.cluster = fixture.cluster;
  ICF_ASSERT_OK(bench.coordinator().handle_admin(upsert_cluster, result));
  wire::AdminMessage upsert_link;
  upsert_link.action = wire::AdminAction::UpsertLink;
  upsert_link.link = make_link("edge-xy", fixture.endpoint, peer.endpoint);
  ICF_ASSERT_OK(bench.coordinator().handle_admin(upsert_link, result));
  wire::AdminMessage upsert_path;
  upsert_path.action = wire::AdminAction::UpsertPath;
  upsert_path.path = make_path("path-xy", fixture.endpoint, peer.endpoint, {"edge-xy"});
  ICF_ASSERT_OK(bench.coordinator().handle_admin(upsert_path, result));
  wire::AdminMessage upsert_policy;
  upsert_policy.action = wire::AdminAction::UpsertPolicy;
  upsert_policy.policy = allow_rule("allow-xy", "domain-north", ClusterId{}, ClusterId{}, 1);
  ICF_ASSERT_OK(bench.coordinator().handle_admin(upsert_policy, result));

  wire::AdminMessage erase;
  erase.action = wire::AdminAction::DeletePolicy;
  erase.policy_id = "allow-xy";
  ICF_ASSERT_OK(bench.coordinator().handle_admin(erase, result));
  erase = wire::AdminMessage{};
  erase.action = wire::AdminAction::DeletePath;
  erase.edge = EdgeId::parse("path-xy").value();
  ICF_ASSERT_OK(bench.coordinator().handle_admin(erase, result));
  erase = wire::AdminMessage{};
  erase.action = wire::AdminAction::DeleteLink;
  erase.edge = EdgeId::parse("edge-xy").value();
  ICF_ASSERT_OK(bench.coordinator().handle_admin(erase, result));
  erase = wire::AdminMessage{};
  erase.action = wire::AdminAction::DeleteCluster;
  erase.cluster_id = fixture.cluster.id;
  ICF_ASSERT_OK(bench.coordinator().handle_admin(erase, result));

  ICF_ASSERT_OK(bench.restart());
  ICF_EXPECT_TRUE(bench.registry().clusters().empty());
  ICF_EXPECT_TRUE(bench.registry().links().empty());
  ICF_EXPECT_TRUE(bench.registry().paths().empty());
  ICF_EXPECT_TRUE(bench.registry().policies().empty());
}

// ---- over loopback TCP, in the role of the cluster agents ---------------------------------------

namespace {

// The incarnation the protocol client presents in its handshake.
IncarnationId client_incarnation() {
  return IncarnationId::from_uuid(Uuid::parse("11111111-2222-4333-8444-555555555555").value());
}

struct LiveAgent {
  client::Client client;
  ClusterId cluster;
  AuthorityDomainId domain;
  EndpointId endpoint;
};

// Reads frames until one of the wanted type arrives. Whatever else the coordinator sends in
// between (keep-alives, status requests) is skipped.
Result<wire::Frame> await_frame(client::Client& client, wire::MessageType type, Duration deadline,
                                const Clock& clock) {
  const std::int64_t limit = clock.monotonic_nanos() + deadline.nanos();
  for (;;) {
    const std::int64_t remaining = limit - clock.monotonic_nanos();
    if (remaining <= 0) {
      return Status::make(Outcome::Unreachable, std::string("no ") + wire::to_string(type) + " frame arrived");
    }
    Result<wire::Frame> frame = client.receive_frame(Duration::from_nanos(remaining));
    if (!frame) {
      return frame.status();
    }
    if (frame.value().header.type == type) {
      return frame;
    }
  }
}

template <class Message>
void send(client::Client& client, wire::MessageType type, const Message& message) {
  Result<std::vector<std::byte>> payload = wire::encode_message(message);
  ICF_ASSERT_OK(payload.status());
  ICF_ASSERT_OK(client.send_frame(type, payload.value()));
}

LiveAgent connect_agent(const CoordinatorHarness& harness, const std::string& cluster, const std::string& domain,
                        const std::string& endpoint) {
  client::ClientOptions options;
  options.host = "127.0.0.1";
  options.port = harness.port();
  options.role = wire::PeerRole::Agent;
  options.cluster = ClusterId::parse(cluster).value();
  options.domain = AuthorityDomainId::parse(domain).value();
  Result<client::Client> connected = client::Client::connect(options, harness.clock());
  ICF_ASSERT_OK(connected.status());
  ICF_ASSERT_TRUE(connected.value().hello_ack().outcome == Outcome::Ok);
  LiveAgent agent;
  agent.client = std::move(connected.value());
  agent.cluster = options.cluster;
  agent.domain = options.domain;
  agent.endpoint = EndpointId::parse(endpoint).value();
  return agent;
}

void report(LiveAgent& agent, const CoordinatorHarness& harness) {
  wire::ReportClusterMessage message;
  message.session = agent.client.hello_ack().session;
  message.cluster.id = agent.cluster;
  message.cluster.domain = agent.domain;
  message.cluster.incarnation = client_incarnation();
  message.cluster.generation = Generation(1);
  message.cluster.policy_generation = PolicyGeneration(1);
  message.cluster.state = model::ClusterState::Active;
  message.cluster.endpoints.push_back(
      endpoint_for(agent.cluster, agent.endpoint.str(), "/" + agent.endpoint.str(), 100, PolicyGeneration(1)));
  send(agent.client, wire::MessageType::ReportCluster, message);
  Result<wire::Frame> reply = await_frame(agent.client, wire::MessageType::ReportAck, Duration::from_seconds(10),
                                          harness.clock());
  ICF_ASSERT_OK(reply.status());
  ByteReader reader(reply.value().payload);
  Result<wire::ReportAckMessage> ack = wire::decode_report_ack(reader);
  ICF_ASSERT_OK(ack.status());
  ICF_ASSERT_TRUE(ack.value().outcome == Outcome::Ok);
}

client::Client connect_operator(const CoordinatorHarness& harness) {
  client::ClientOptions options;
  options.host = "127.0.0.1";
  options.port = harness.port();
  Result<client::Client> connected = client::Client::connect(options, harness.clock());
  ICF_ASSERT_OK(connected.status());
  return std::move(connected.value());
}

model::GrantState grant_state(client::Client& observer, const GrantId& grant, Rng& rng) {
  wire::QueryMessage query;
  query.kind = wire::QueryKind::ShowGrant;
  query.grant = grant;
  query.request = Uuid::random(rng);
  Result<wire::QueryResultMessage> result = observer.query(query);
  ICF_ASSERT_OK(result.status());
  ICF_ASSERT_TRUE(result.value().grants.size() == 1);
  return result.value().grants.front().state;
}

// Polls the grant until it reaches the wanted state or the bound elapses.
bool grant_reaches(client::Client& observer, const GrantId& grant, model::GrantState wanted, Rng& rng) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (std::chrono::steady_clock::now() < deadline) {
    if (grant_state(observer, grant, rng) == wanted) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return false;
}

struct LiveGrant {
  GrantId grant;
  AttemptId attempt;
};

// As the operator: proposes a contract and issues a grant. As the two agents: consents, prepares,
// and waits for the commit request. Returns with the commit request received on both sides.
LiveGrant prepare_grant(const CoordinatorHarness& harness, client::Client& observer, LiveAgent& a, LiveAgent& b,
                        Rng& rng) {
  wire::AdminMessage propose;
  propose.request = Uuid::random(rng);
  propose.action = wire::AdminAction::AuthorizeContract;
  propose.cluster_id = a.cluster;
  propose.endpoint = a.endpoint;
  propose.cluster_b = b.cluster;
  propose.endpoint_b = b.endpoint;
  propose.capacity = CapacityUnits(40);
  propose.lease_duration = Duration::from_seconds(120);
  Result<wire::AdminResultMessage> proposed = observer.admin(propose);
  ICF_ASSERT_OK(proposed.status());
  ICF_ASSERT_TRUE(proposed.value().outcome == Outcome::Ok);
  const ContractId contract = proposed.value().contract;

  for (LiveAgent* agent : {&a, &b}) {
    Result<wire::Frame> frame = await_frame(agent->client, wire::MessageType::ProposeContract,
                                            Duration::from_seconds(10), harness.clock());
    ICF_ASSERT_OK(frame.status());
    ByteReader reader(frame.value().payload);
    Result<wire::ProposeContractMessage> proposal = wire::decode_propose_contract(reader);
    ICF_ASSERT_OK(proposal.status());
    wire::ContractConsentMessage consent;
    consent.session = agent->client.hello_ack().session;
    consent.contract = proposal.value().contract;
    consent.terms_digest = proposal.value().terms.digest();
    consent.decision = model::ConsentDecision::Accepted;
    consent.endpoint = agent->endpoint;
    consent.incarnation = client_incarnation();
    consent.generation = Generation(1);
    consent.policy_generation = PolicyGeneration(1);
    consent.agent_term = Term(1);
    consent.reason = "accepted";
    ICF_ASSERT_OK(agent->client.send_consent(consent));
  }
  // The consents travel on the agents' own connections; wait until the coordinator has both.
  bool consented = false;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (!consented && std::chrono::steady_clock::now() < deadline) {
    wire::QueryMessage query;
    query.kind = wire::QueryKind::ShowContract;
    query.contract = contract;
    query.request = Uuid::random(rng);
    Result<wire::QueryResultMessage> shown = observer.query(query);
    ICF_ASSERT_OK(shown.status());
    consented = !shown.value().contracts.empty() &&
                shown.value().contracts.front().state == model::ContractState::Consented;
    if (!consented) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }
  ICF_ASSERT_TRUE(consented);

  wire::AdminMessage issue;
  issue.request = Uuid::random(rng);
  issue.action = wire::AdminAction::IssueGrant;
  issue.contract = contract;
  Result<wire::AdminResultMessage> issued = observer.admin(issue);
  ICF_ASSERT_OK(issued.status());
  ICF_ASSERT_TRUE(issued.value().outcome == Outcome::Ok);

  LiveGrant live;
  live.grant = issued.value().grant;
  for (LiveAgent* agent : {&a, &b}) {
    Result<wire::Frame> frame = await_frame(agent->client, wire::MessageType::PrepareGrant,
                                            Duration::from_seconds(10), harness.clock());
    ICF_ASSERT_OK(frame.status());
    ByteReader reader(frame.value().payload);
    Result<wire::PrepareGrantMessage> prepare = wire::decode_prepare_grant(reader);
    ICF_ASSERT_OK(prepare.status());
    live.attempt = prepare.value().grant.attempt;
    wire::GrantPreparedMessage prepared;
    prepared.session = agent->client.hello_ack().session;
    prepared.grant = live.grant;
    prepared.attempt = live.attempt;
    prepared.accepted = true;
    prepared.agent_term = Term(1);
    prepared.detail = "prepared";
    send(agent->client, wire::MessageType::GrantPrepared, prepared);
  }
  for (LiveAgent* agent : {&a, &b}) {
    ICF_ASSERT_OK(await_frame(agent->client, wire::MessageType::CommitGrant, Duration::from_seconds(10),
                              harness.clock())
                      .status());
  }
  return live;
}

void acknowledge_commit(LiveAgent& agent, const LiveGrant& live, bool installed) {
  wire::GrantCommittedMessage committed;
  committed.session = agent.client.hello_ack().session;
  committed.grant = live.grant;
  committed.attempt = live.attempt;
  committed.installed = installed;
  committed.agent_term = Term(1);
  committed.detail = installed ? "enforced" : "the grant cannot be installed";
  send(agent.client, wire::MessageType::GrantCommitted, committed);
}

}  // namespace

ICF_TEST(coordinator, an_aborted_grant_is_withdrawn_from_the_agent_that_installed_it) {
  CoordinatorHarness harness("coord-abort-delivery");
  ICF_ASSERT_TRUE(harness.valid());
  Rng rng(94);
  LiveAgent a = connect_agent(harness, "cluster-a", "domain-north", "a-scope");
  LiveAgent b = connect_agent(harness, "cluster-b", "domain-south", "b-scope");
  report(a, harness);
  report(b, harness);
  client::Client observer = connect_operator(harness);
  const LiveGrant live = prepare_grant(harness, observer, a, b, rng);

  // One side installs the grant, the other cannot. The coordinator abandons the attempt, and the
  // side that already enforces it has to be told.
  acknowledge_commit(a, live, true);
  acknowledge_commit(b, live, false);
  Result<wire::Frame> frame = await_frame(a.client, wire::MessageType::AbortGrant, Duration::from_seconds(3),
                                          harness.clock());
  ICF_ASSERT_OK(frame.status());
  ByteReader reader(frame.value().payload);
  Result<wire::AbortGrantMessage> abort = wire::decode_abort_grant(reader);
  ICF_ASSERT_OK(abort.status());
  ICF_EXPECT_EQ(live.grant, abort.value().grant);
  ICF_EXPECT_EQ(live.attempt, abort.value().attempt);
  ICF_EXPECT_TRUE(grant_reaches(observer, live.grant, model::GrantState::Aborted, rng));

  // The agent's answer to the abort changes nothing.
  wire::GrantAbortedMessage answer;
  answer.session = a.client.hello_ack().session;
  answer.grant = live.grant;
  answer.attempt = live.attempt;
  answer.reason = "abandoned";
  send(a.client, wire::MessageType::GrantAborted, answer);
  ICF_EXPECT_FALSE(await_frame(a.client, wire::MessageType::AbortGrant, Duration::from_millis(300), harness.clock())
                       .has_value());
  ICF_EXPECT_TRUE(grant_state(observer, live.grant, rng) == model::GrantState::Aborted);
}

ICF_TEST(coordinator, an_agent_that_missed_a_fence_is_told_when_it_reports_its_enforcement) {
  CoordinatorHarness harness("coord-missed-fence");
  ICF_ASSERT_TRUE(harness.valid());
  Rng rng(95);
  LiveAgent a = connect_agent(harness, "cluster-a", "domain-north", "a-scope");
  LiveAgent b = connect_agent(harness, "cluster-b", "domain-south", "b-scope");
  report(a, harness);
  report(b, harness);
  client::Client observer = connect_operator(harness);
  const LiveGrant live = prepare_grant(harness, observer, a, b, rng);
  acknowledge_commit(a, live, true);
  acknowledge_commit(b, live, true);
  ICF_ASSERT_TRUE(grant_reaches(observer, live.grant, model::GrantState::Committed, rng));

  // The agent of cluster A loses its connection, and the operator fences the grant meanwhile.
  a.client.close();
  wire::AdminMessage fence;
  fence.request = Uuid::random(rng);
  fence.action = wire::AdminAction::FenceGrant;
  fence.grant = live.grant;
  Result<wire::AdminResultMessage> fenced = observer.admin(fence);
  ICF_ASSERT_OK(fenced.status());
  ICF_ASSERT_TRUE(fenced.value().outcome == Outcome::Ok);

  // The same agent process reconnects and reports that it still enforces the grant.
  LiveAgent again = connect_agent(harness, "cluster-a", "domain-north", "a-scope");
  Result<wire::Frame> request = await_frame(again.client, wire::MessageType::StatusRequest,
                                            Duration::from_seconds(10), harness.clock());
  ICF_ASSERT_OK(request.status());
  ByteReader request_reader(request.value().payload);
  Result<wire::StatusRequestMessage> asked = wire::decode_status_request(request_reader);
  ICF_ASSERT_OK(asked.status());
  wire::StatusReportMessage status;
  status.session = again.client.hello_ack().session;
  status.request = asked.value().request;
  status.cluster = again.cluster;
  status.incarnation = client_incarnation();
  status.generation = Generation(1);
  status.policy_generation = PolicyGeneration(1);
  status.agent_term = Term(1);
  wire::GrantStatusEntry entry;
  entry.grant = live.grant;
  entry.attempt = live.attempt;
  entry.state = model::GrantState::Active;
  entry.agent_term = again.client.hello_ack().coordinator_term;
  status.grants.push_back(entry);
  send(again.client, wire::MessageType::StatusReport, status);

  Result<wire::Frame> frame = await_frame(again.client, wire::MessageType::Fence, Duration::from_seconds(3),
                                          harness.clock());
  ICF_ASSERT_OK(frame.status());
  ByteReader reader(frame.value().payload);
  Result<wire::FenceMessage> told = wire::decode_fence(reader);
  ICF_ASSERT_OK(told.status());
  ICF_ASSERT_TRUE(told.value().grants.size() == 1);
  ICF_EXPECT_EQ(live.grant, told.value().grants.front());
  ICF_EXPECT_TRUE(grant_state(observer, live.grant, rng) == model::GrantState::Fenced);
}

ICF_TEST(coordinator, an_agent_with_a_long_grant_history_answers_the_status_request) {
  // An agent keeps a record of every grant it ever prepared. Its answer to the status request
  // has to fit one frame however long that history is.
  CoordinatorHarness harness("coord-long-history");
  ICF_ASSERT_TRUE(harness.valid());
  TempDir state("agent-long-history");
  Rng rng(96);
  const ClusterId cluster = ClusterId::parse("cluster-a").value();
  {
    store::DurableStore::Options options;
    options.directory = state.path();
    options.snapshot_name = "agent.snapshot";
    options.wal_name = "agent.wal";
    options.durable = false;
    store::DurableStore::Recovery recovery;
    Result<store::DurableStore> store = store::DurableStore::open(options, recovery);
    ICF_ASSERT_OK(store.status());
    store::Mutation mutation;
    mutation.kind = store::MutationKind::ContractPut;
    mutation.contract.id = ContractId::random(rng);
    mutation.contract.parties[0] = model::PartyRef{cluster, EndpointId::parse("a-scope").value(),
                                                  AuthorityDomainId::parse("domain-north").value()};
    mutation.contract.parties[1] = model::PartyRef{ClusterId::parse("cluster-b").value(),
                                                  EndpointId::parse("b-scope").value(),
                                                  AuthorityDomainId::parse("domain-south").value()};
    mutation.contract.capacity = CapacityUnits(10);
    mutation.contract.lease_duration = Duration::from_seconds(120);
    ICF_ASSERT_OK(store.value().append(mutation, Timestamp::from_unix_nanos(1)).status());
    const ContractId contract = mutation.contract.id;
    mutation = store::Mutation{};
    mutation.kind = store::MutationKind::GrantPut;
    mutation.grant.contract = contract;
    mutation.grant.state = model::GrantState::Fenced;
    mutation.grant.issued_at = Timestamp::from_unix_nanos(1);
    mutation.grant.valid_until = Timestamp::from_unix_nanos(2);
    for (int index = 0; index < 15000; ++index) {
      mutation.grant.id = GrantId::random(rng);
      mutation.grant.attempt = AttemptId::random(rng);
      ICF_ASSERT_OK(store.value().append(mutation, Timestamp::from_unix_nanos(2)).status());
    }
  }

  runtime::Agent::Config config;
  config.cluster = cluster;
  config.domain = AuthorityDomainId::parse("domain-north").value();
  config.generation = Generation(1);
  config.endpoints.push_back(endpoint_for(cluster, "a-scope", "/a-scope", 100, PolicyGeneration(1)));
  config.coordinator_port = harness.port();
  config.state_directory = state.path();
  config.durable = false;
  client::Client observer = connect_operator(harness);
  Result<std::unique_ptr<runtime::Agent>> created = runtime::Agent::create(config, harness.clock());
  ICF_ASSERT_OK(created.status());
  runtime::Agent& agent = *created.value();
  std::thread serving([&agent]() { (void)agent.serve(); });

  bool answered = false;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
  while (!answered && std::chrono::steady_clock::now() < deadline) {
    wire::QueryMessage query;
    query.kind = wire::QueryKind::Status;
    query.request = Uuid::random(rng);
    Result<wire::QueryResultMessage> result = observer.query(query);
    if (result && result.value().status.has_value()) {
      answered = result.value().status->revalidations > 0;
    }
    if (!answered) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  }
  agent.stop();
  serving.join();
  ICF_EXPECT_TRUE(answered);
}
