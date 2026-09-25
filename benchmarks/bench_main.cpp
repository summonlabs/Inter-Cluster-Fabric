// icf-bench - completed-work measurements for the Inter-Cluster Fabric runtime.
//
// Every number this program prints is measured on the machine it runs on. Nothing is estimated
// or extrapolated. Scenarios:
//   codec   frame and message encode/decode throughput
//   store   durable log append throughput (with fsync) and snapshot compaction cost
//   engine  authorization decisions per second over a synthetic model
//   rpc     real loopback TCP round trips against a live coordinator (connect, handshake, query)
//   flow    end-to-end two-sided contract and grant commit rate with two cluster agents
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "app_support.hpp"
#include "icf/client/client.hpp"
#include "icf/core/log.hpp"
#include "icf/store/file_util.hpp"
#include "icf/runtime/agent.hpp"
#include "icf/runtime/coordinator.hpp"
#include "icf/version.hpp"

namespace {

using Clock = std::chrono::steady_clock;

struct Stopwatch {
  Clock::time_point start = Clock::now();
  [[nodiscard]] double elapsed_seconds() const {
    return std::chrono::duration<double>(Clock::now() - start).count();
  }
};

struct Latencies {
  std::vector<double> micros;

  void add(double value) { micros.push_back(value); }

  [[nodiscard]] double percentile(double fraction) const {
    if (micros.empty()) {
      return 0.0;
    }
    std::vector<double> sorted = micros;
    std::sort(sorted.begin(), sorted.end());
    const std::size_t index = static_cast<std::size_t>(fraction * static_cast<double>(sorted.size() - 1));
    return sorted[index];
  }

  [[nodiscard]] double mean() const {
    if (micros.empty()) {
      return 0.0;
    }
    double total = 0.0;
    for (const double value : micros) {
      total += value;
    }
    return total / static_cast<double>(micros.size());
  }
};

// Every benchmark that touches durable state starts from an empty directory, so a second run
// measures the same work as the first and never inherits a previous run's generations.
std::string temporary_directory(const char* name) {
  const std::string base = "icf-bench-" + std::string(name);
  std::error_code error;
  std::filesystem::remove_all(base, error);
  std::filesystem::create_directories(base, error);
  return base;
}

void remove_tree(const std::string& path) {
  std::error_code error;
  std::filesystem::remove_all(path, error);
}

void bench_codec(std::uint64_t iterations) {
  icf::wire::HelloMessage hello;
  hello.role = icf::wire::PeerRole::Agent;
  hello.cluster = icf::ClusterId::parse("bench-cluster").value();
  hello.domain = icf::AuthorityDomainId::parse("bench-domain").value();
  icf::Rng rng(1);
  hello.incarnation = icf::IncarnationId::random(rng);
  hello.generation = icf::Generation(7);
  hello.policy_generation = icf::PolicyGeneration(3);
  hello.agent_term = icf::Term(11);
  hello.capabilities = icf::wire::kCapabilityAll;
  const icf::Result<std::vector<std::byte>> payload = icf::wire::encode_message(hello);

  Stopwatch encode_watch;
  std::size_t payload_bytes = 0;
  for (std::uint64_t index = 0; index < iterations; ++index) {
    const icf::Result<std::vector<std::byte>> encoded = icf::wire::encode_message(hello);
    payload_bytes += encoded.value().size();
  }
  const double encode_seconds = encode_watch.elapsed_seconds();

  const std::vector<std::byte> bytes = payload.value();
  Stopwatch decode_watch;
  for (std::uint64_t index = 0; index < iterations; ++index) {
    icf::ByteReader reader(bytes);
    const icf::Result<icf::wire::HelloMessage> decoded = icf::wire::decode_hello(reader);
    if (!decoded) {
      std::fprintf(stderr, "bench: decode failed\n");
      std::exit(1);
    }
  }
  const double decode_seconds = decode_watch.elapsed_seconds();

  Stopwatch frame_watch;
  std::vector<std::byte> framed;
  for (std::uint64_t index = 0; index < iterations; ++index) {
    framed.clear();
    icf::wire::FrameHeader header;
    header.version = icf::limits::kProtocolVersionMax;
    header.type = icf::wire::MessageType::Hello;
    if (!icf::wire::append_frame(framed, header, bytes, {})) {
      std::fprintf(stderr, "bench: frame failed\n");
      std::exit(1);
    }
  }
  const double frame_seconds = frame_watch.elapsed_seconds();

  Stopwatch parse_watch;
  for (std::uint64_t index = 0; index < iterations; ++index) {
    icf::wire::FrameParser parser;
    (void)parser.push(framed);
    const icf::Result<std::optional<icf::wire::Frame>> frame = parser.next({});
    if (!frame.value().has_value()) {
      std::fprintf(stderr, "bench: parse failed\n");
      std::exit(1);
    }
  }
  const double parse_seconds = parse_watch.elapsed_seconds();

  std::printf("codec  hello encode      %10.0f ops/s  (%zu byte payload)\n",
              static_cast<double>(iterations) / encode_seconds, payload_bytes / iterations);
  std::printf("codec  hello decode      %10.0f ops/s\n", static_cast<double>(iterations) / decode_seconds);
  std::printf("codec  frame append      %10.0f ops/s\n", static_cast<double>(iterations) / frame_seconds);
  std::printf("codec  frame parse       %10.0f ops/s\n", static_cast<double>(iterations) / parse_seconds);
}

void bench_store(std::uint64_t iterations, bool durable) {
  const std::string directory = temporary_directory("store");
  (void)icf::store::ensure_directory(directory);
  icf::store::DurableStore::Options options;
  options.directory = directory;
  options.snapshot_name = "bench.snapshot";
  options.wal_name = "bench.wal";
  options.durable = durable;
  options.compact_bytes = 1ull << 30;
  options.compact_records = 1ull << 30;
  icf::store::DurableStore::Recovery recovery;
  icf::Result<icf::store::DurableStore> store = icf::store::DurableStore::open(options, recovery);
  if (!store) {
    std::fprintf(stderr, "bench: store open failed: %s\n", store.status().to_string().c_str());
    std::exit(1);
  }
  icf::model::AuditRecord record;
  record.sequence = icf::Sequence(1);
  record.actor = "bench";
  record.action = "append";
  record.subject = "bench-subject";
  record.outcome = icf::Outcome::Ok;
  record.detail = "durable log append benchmark record";

  Stopwatch watch;
  for (std::uint64_t index = 0; index < iterations; ++index) {
    icf::store::Mutation mutation;
    mutation.kind = icf::store::MutationKind::AuditAppend;
    record.sequence = icf::Sequence(index + 1);
    mutation.audit = record;
    const icf::Result<icf::Sequence> appended = store.value().append(mutation, icf::Timestamp::from_unix_nanos(1));
    if (!appended) {
      std::fprintf(stderr, "bench: append failed: %s\n", appended.status().to_string().c_str());
      std::exit(1);
    }
  }
  const double seconds = watch.elapsed_seconds();
  const std::uint64_t appended_records = store.value().wal_records();
  const std::uint64_t appended_bytes = store.value().wal_bytes();

  icf::model::Registry registry;
  Stopwatch compact_watch;
  const icf::Status compacted =
      store.value().compact(registry, icf::store::StoreMeta{}, icf::Timestamp::from_unix_nanos(2));
  const double compact_seconds = compact_watch.elapsed_seconds();
  if (!compacted) {
    std::fprintf(stderr, "bench: compaction failed: %s\n", compacted.message().c_str());
    std::exit(1);
  }
  std::printf("store  durable append      %10.0f ops/s  (%s fsync, %llu records, %llu bytes)\n",
              static_cast<double>(iterations) / seconds, durable ? "with" : "without",
              static_cast<unsigned long long>(appended_records),
              static_cast<unsigned long long>(appended_bytes));
  std::printf("store  empty compaction    %10.3f ms\n", compact_seconds * 1000.0);
  remove_tree(directory);
}

icf::model::Registry build_model(std::size_t cluster_count, std::size_t endpoints_per_cluster) {
  icf::Rng rng(20260101);
  icf::model::Registry registry;
  for (std::size_t cluster_index = 0; cluster_index < cluster_count; ++cluster_index) {
    icf::model::ClusterRecord cluster;
    cluster.id = icf::ClusterId::parse("bench-c" + std::to_string(cluster_index)).value();
    cluster.domain = icf::AuthorityDomainId::parse("bench-d" + std::to_string(cluster_index % 4)).value();
    cluster.incarnation = icf::IncarnationId::random(rng);
    cluster.generation = icf::Generation(5);
    cluster.policy_generation = icf::PolicyGeneration(1);
    cluster.state = icf::model::ClusterState::Active;
    cluster.provenance.source = icf::model::EvidenceSource::AdminConfigured;
    cluster.provenance.verification = icf::model::VerificationState::Verified;
    for (std::size_t endpoint_index = 0; endpoint_index < endpoints_per_cluster; ++endpoint_index) {
      icf::model::EndpointRecord endpoint;
      endpoint.id = icf::EndpointId::parse("bench-c" + std::to_string(cluster_index) + "-e" +
                                           std::to_string(endpoint_index))
                        .value();
      endpoint.cluster = cluster.id;
      endpoint.scope = icf::ScopeName::parse("/bench/" + std::to_string(endpoint_index)).value();
      endpoint.capacity = icf::CapacityUnits(100000);
      endpoint.policy_generation = cluster.policy_generation;
      endpoint.state = icf::model::EndpointState::Active;
      endpoint.inter_cluster_allowed = true;
      endpoint.permits_degraded = true;
      endpoint.provenance.source = icf::model::EvidenceSource::AdminConfigured;
      endpoint.provenance.verification = icf::model::VerificationState::Verified;
      cluster.endpoints.push_back(endpoint);
    }
    (void)registry.put_cluster(cluster);
    icf::model::PolicyRule rule;
    rule.id = "allow-" + cluster.id.str();
    rule.owner = cluster.domain;
    rule.generation = icf::PolicyGeneration(1);
    rule.allow = true;
    rule.allow_degraded = true;
    rule.provenance.source = icf::model::EvidenceSource::AdminConfigured;
    rule.provenance.verification = icf::model::VerificationState::Verified;
    (void)registry.put_policy(rule);
  }
  return registry;
}

void bench_engine(std::uint64_t iterations) {
  icf::Rng rng(7);
  icf::model::Registry registry = build_model(32, 4);
  icf::runtime::EngineView view;
  view.term = icf::Term(1);
  view.incarnation = icf::IncarnationId::random(rng);
  view.now = icf::Timestamp::from_unix_nanos(1000000000);

  // Add everything a decision needs for the measured pair, so the authorized path (contract,
  // consent, grant, capacity, path accounting) is what is being timed.
  const icf::model::ClusterRecord* source = registry.find_cluster(icf::ClusterId::parse("bench-c0").value());
  const icf::model::ClusterRecord* target = registry.find_cluster(icf::ClusterId::parse("bench-c1").value());
  const icf::EndpointId source_endpoint = source->endpoints.front().id;
  const icf::EndpointId target_endpoint = target->endpoints.front().id;
  icf::model::LinkRecord link;
  link.id = icf::EdgeId::parse("bench-edge").value();
  link.a = source_endpoint;
  link.b = target_endpoint;
  link.kind = icf::model::LinkKind::LoopbackTcp;
  link.state = icf::model::LinkState::Up;
  link.capacity = icf::CapacityUnits(100000);
  link.provenance.source = icf::model::EvidenceSource::AdminConfigured;
  link.provenance.verification = icf::model::VerificationState::Verified;
  (void)registry.put_link(link);
  icf::model::PathRecord path;
  path.id = icf::PathId::parse("bench-path").value();
  path.a = source_endpoint;
  path.b = target_endpoint;
  path.hops.push_back(link.id);
  path.provenance.source = icf::model::EvidenceSource::DerivedFromTopology;
  path.provenance.verification = icf::model::VerificationState::Verified;
  (void)registry.put_path(path);
  registry.recompute_path_states();
  for (const char* domain : {"bench-d0", "bench-d1"}) {
    icf::model::PolicyRule rule;
    rule.id = std::string("bench-allow-") + domain;
    rule.owner = icf::AuthorityDomainId::parse(domain).value();
    rule.cluster_a = source->id;
    rule.cluster_b = target->id;
    rule.generation = icf::PolicyGeneration(1);
    rule.allow = true;
    rule.allow_degraded = true;
    rule.provenance.source = icf::model::EvidenceSource::AdminConfigured;
    rule.provenance.verification = icf::model::VerificationState::Verified;
    (void)registry.put_policy(rule);
  }
  icf::model::ContractRecord contract;
  contract.id = icf::ContractId::random(rng);
  contract.parties[0] = icf::model::PartyRef{source->id, source_endpoint, source->domain};
  contract.parties[1] = icf::model::PartyRef{target->id, target_endpoint, target->domain};
  contract.capacity = icf::CapacityUnits(100000);
  contract.lease_duration = icf::Duration::from_minutes(10);
  contract.state = icf::model::ContractState::Consented;
  contract.created_at = view.now;
  contract.updated_at = view.now;
  contract.provenance.source = icf::model::EvidenceSource::DerivedFromTopology;
  contract.provenance.verification = icf::model::VerificationState::Verified;
  icf::model::ContractTerms terms;
  terms.parties = contract.parties;
  terms.capacity = contract.capacity;
  terms.lease_duration = contract.lease_duration;
  terms.incarnations = {source->incarnation, target->incarnation};
  terms.generations = {source->generation, target->generation};
  terms.policies = {source->policy_generation, target->policy_generation};
  terms.proposed_at = view.now;
  contract.terms_digest = terms.digest();
  for (std::size_t side = 0; side < icf::model::kPartyCount; ++side) {
    const icf::model::ClusterRecord& cluster = side == 0 ? *source : *target;
    icf::model::ConsentRecord consent;
    consent.cluster = cluster.id;
    consent.endpoint = cluster.endpoints.front().id;
    consent.incarnation = cluster.incarnation;
    consent.generation = cluster.generation;
    consent.policy_generation = cluster.policy_generation;
    consent.agent_term = icf::Term(1);
    consent.terms_digest = contract.terms_digest;
    consent.decision = icf::model::ConsentDecision::Accepted;
    consent.decided_at = view.now;
    contract.consents[side] = consent;
  }
  (void)registry.put_contract(contract);
  icf::model::GrantRecord grant;
  grant.id = icf::GrantId::random(rng);
  grant.contract = contract.id;
  grant.terms_digest = contract.terms_digest;
  grant.coordinator_term = view.term;
  grant.coordinator = view.incarnation;
  grant.attempt = icf::AttemptId::random(rng);
  grant.incarnations = {source->incarnation, target->incarnation};
  grant.generations = {source->generation, target->generation};
  grant.policies = {source->policy_generation, target->policy_generation};
  grant.capacity = icf::CapacityUnits(100000);
  grant.issued_at = view.now;
  grant.valid_until = view.now.plus(icf::Duration::from_minutes(10));
  grant.state = icf::model::GrantState::Active;
  grant.acknowledged = {true, true};
  grant.provenance.source = icf::model::EvidenceSource::DerivedFromTopology;
  grant.provenance.verification = icf::model::VerificationState::Verified;
  (void)registry.put_grant(grant);

  icf::model::DecisionQuery query;
  query.source = source_endpoint;
  query.target = target_endpoint;
  query.requested_capacity = icf::CapacityUnits(1);
  {
    Stopwatch watch;
    std::size_t authorized = 0;
    for (std::uint64_t index = 0; index < iterations; ++index) {
      if (icf::runtime::decide(registry, query, view).authorized()) {
        ++authorized;
      }
    }
    const double seconds = watch.elapsed_seconds();
    if (authorized != iterations) {
      std::fprintf(stderr, "bench: the authorized decision path did not authorize every evaluation\n");
      std::exit(1);
    }
    std::printf("engine decide (authorized)  %7.0f ops/s  (registry: %zu clusters, %zu endpoints, "
                "%zu contracts, %zu grants)\n",
                static_cast<double>(iterations) / seconds, registry.clusters().size(),
                registry.counts().endpoints, registry.counts().contracts, registry.counts().grants);
  }
  // The same decision over a pair with no contract measures the early-refusal path.
  icf::model::DecisionQuery refused = query;
  refused.target = target->endpoints[1].id;
  {
    Stopwatch watch;
    for (std::uint64_t index = 0; index < iterations; ++index) {
      (void)icf::runtime::decide(registry, refused, view);
    }
    const double seconds = watch.elapsed_seconds();
    std::printf("engine decide (unauthorized) %6.0f ops/s\n", static_cast<double>(iterations) / seconds);
  }
}

void bench_rpc(std::uint64_t iterations) {
  const std::string directory = temporary_directory("rpc");
  remove_tree(directory);
  icf::SystemClock clock;
  icf::runtime::Coordinator::Config config;
  config.state_directory = directory;
  config.domain = icf::AuthorityDomainId::parse("bench-domain").value();
  config.listen_port = 0;
  config.durable = true;
  icf::Result<std::unique_ptr<icf::runtime::Coordinator>> coordinator =
      icf::runtime::Coordinator::create(config, clock);
  if (!coordinator) {
    std::fprintf(stderr, "bench: coordinator failed: %s\n", coordinator.status().to_string().c_str());
    std::exit(1);
  }
  const std::uint16_t port = coordinator.value()->port();

  // A dedicated thread runs the coordinator event loop: genuine concurrency between the server
  // and the client threads below.
  std::atomic<bool> ready{false};
  std::thread server([&]() {
    ready.store(true);
    (void)coordinator.value()->serve();
  });
  while (!ready.load()) {
  }

  icf::client::ClientOptions options;
  options.host = "127.0.0.1";
  options.port = port;

  Stopwatch connect_watch;
  constexpr std::size_t kConnectIterations = 50;
  for (std::size_t index = 0; index < kConnectIterations; ++index) {
    icf::Result<icf::client::Client> client = icf::client::Client::connect(options, clock);
    if (!client) {
      std::fprintf(stderr, "bench: connect failed: %s\n", client.status().to_string().c_str());
      std::exit(1);
    }
  }
  const double connect_seconds = connect_watch.elapsed_seconds();

  icf::Result<icf::client::Client> client = icf::client::Client::connect(options, clock);
  if (!client) {
    std::fprintf(stderr, "bench: connect failed: %s\n", client.status().to_string().c_str());
    std::exit(1);
  }
  Latencies latencies;
  Stopwatch query_watch;
  for (std::uint64_t index = 0; index < iterations; ++index) {
    icf::wire::QueryMessage query;
    query.kind = icf::wire::QueryKind::Status;
    query.request = icf::Uuid::random(*new icf::Rng(index + 3));
    Stopwatch single;
    const icf::Result<icf::wire::QueryResultMessage> result = client.value().query(query);
    latencies.add(single.elapsed_seconds() * 1e6);
    if (!result) {
      std::fprintf(stderr, "bench: query failed: %s\n", result.status().to_string().c_str());
      std::exit(1);
    }
  }
  const double query_seconds = query_watch.elapsed_seconds();
  std::printf("rpc    connect+handshake  %10.0f ops/s\n", static_cast<double>(kConnectIterations) / connect_seconds);
  std::printf("rpc    status round trip  %10.0f ops/s  (mean %.1f us, p50 %.1f us, p99 %.1f us)\n",
              static_cast<double>(iterations) / query_seconds, latencies.mean(), latencies.percentile(0.50),
              latencies.percentile(0.99));

  coordinator.value()->stop();
  server.join();
  remove_tree(directory);
}

void bench_flow(std::uint64_t iterations) {
  const std::string directory = temporary_directory("flow");
  remove_tree(directory);
  (void)icf::store::ensure_directory(directory);

  icf::SystemClock clock;
  icf::runtime::Coordinator::Config config;
  config.state_directory = directory;
  config.domain = icf::AuthorityDomainId::parse("bench-domain").value();
  config.listen_port = 0;
  icf::Result<std::unique_ptr<icf::runtime::Coordinator>> coordinator = icf::runtime::Coordinator::create(config, clock);
  if (!coordinator) {
    std::fprintf(stderr, "bench: coordinator failed\n");
    std::exit(1);
  }
  const std::uint16_t port = coordinator.value()->port();

  auto make_agent = [&](const char* id, const char* endpoint_id, const char* scope,
                        const std::string& dir, const char* domain) -> std::unique_ptr<icf::runtime::Agent> {
    icf::runtime::Agent::Config agent_config;
    agent_config.cluster = icf::ClusterId::parse(id).value();
    agent_config.domain = icf::AuthorityDomainId::parse(domain).value();
    agent_config.generation = icf::Generation(1);
    agent_config.policy_generation = icf::PolicyGeneration(1);
    agent_config.coordinator_host = "127.0.0.1";
    agent_config.coordinator_port = port;
    agent_config.state_directory = dir;
    agent_config.control_port = 0;
    icf::model::EndpointRecord endpoint;
    endpoint.id = icf::EndpointId::parse(endpoint_id).value();
    endpoint.cluster = agent_config.cluster;
    endpoint.scope = icf::ScopeName::parse(scope).value();
    endpoint.capacity = icf::CapacityUnits(100000);
    endpoint.policy_generation = icf::PolicyGeneration(1);
    endpoint.state = icf::model::EndpointState::Active;
    endpoint.inter_cluster_allowed = true;
    endpoint.permits_degraded = true;
    endpoint.provenance.source = icf::model::EvidenceSource::AdminConfigured;
    endpoint.provenance.verification = icf::model::VerificationState::Verified;
    agent_config.endpoints.push_back(endpoint);
    icf::Result<std::unique_ptr<icf::runtime::Agent>> agent = icf::runtime::Agent::create(agent_config, clock);
    if (!agent) {
      std::fprintf(stderr, "bench: agent failed: %s\n", agent.status().to_string().c_str());
      std::exit(1);
    }
    return std::move(agent.value());
  };

  std::unique_ptr<icf::runtime::Agent> agent_a =
      make_agent("bench-a", "bench-a-e0", "/bench/a", directory + "/agent-a", "bench-north");
  std::unique_ptr<icf::runtime::Agent> agent_b =
      make_agent("bench-b", "bench-b-e0", "/bench/b", directory + "/agent-b", "bench-south");

  std::atomic<bool> ready{false};
  std::thread server([&]() {
    ready.store(true);
    (void)coordinator.value()->serve();
  });
  std::thread agent_a_thread([&]() { (void)agent_a->serve(); });
  std::thread agent_b_thread([&]() { (void)agent_b->serve(); });
  while (!ready.load()) {
  }

  // Everything the benchmark does to the running system goes through a real client connection on
  // loopback, so the measurement covers the same path an operator uses, and the coordinator's
  // single-threaded state is never touched from the benchmark thread.
  icf::client::ClientOptions options;
  options.host = "127.0.0.1";
  options.port = port;
  icf::Result<icf::client::Client> client = icf::client::Client::connect(options, clock);
  if (!client) {
    std::fprintf(stderr, "bench: client connect failed: %s\n", client.status().to_string().c_str());
    std::exit(1);
  }
  icf::Rng request_rng(4242);
  auto query = [&](icf::wire::QueryMessage message) -> icf::Result<icf::wire::QueryResultMessage> {
    message.request = icf::Uuid::random(request_rng);
    return client.value().query(message);
  };
  auto admin = [&](icf::wire::AdminMessage message) -> icf::Result<icf::wire::AdminResultMessage> {
    message.request = icf::Uuid::random(request_rng);
    return client.value().admin(message);
  };

  // Wait until both agents have registered their endpoint scopes.
  const auto registration_deadline = Clock::now() + std::chrono::seconds(20);
  for (;;) {
    icf::wire::QueryMessage clusters_query;
    clusters_query.kind = icf::wire::QueryKind::ListClusters;
    icf::Result<icf::wire::QueryResultMessage> clusters = query(clusters_query);
    if (clusters) {
      std::size_t with_endpoints = 0;
      for (const icf::model::ClusterRecord& cluster : clusters.value().clusters) {
        if (!cluster.endpoints.empty()) {
          ++with_endpoints;
        }
      }
      if (with_endpoints >= 2) {
        break;
      }
    }
    if (Clock::now() > registration_deadline) {
      std::fprintf(stderr, "bench: the cluster agents did not register in time\n");
      std::exit(1);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }

  for (const char* domain : {"bench-north", "bench-south"}) {
    icf::wire::AdminMessage message;
    message.action = icf::wire::AdminAction::UpsertPolicy;
    icf::model::PolicyRule rule;
    rule.id = std::string("allow-") + domain;
    rule.owner = icf::AuthorityDomainId::parse(domain).value();
    rule.cluster_a = icf::ClusterId::parse("bench-a").value();
    rule.cluster_b = icf::ClusterId::parse("bench-b").value();
    rule.allow = true;
    rule.allow_degraded = true;
    rule.generation = icf::PolicyGeneration(1);
    rule.provenance.source = icf::model::EvidenceSource::AdminConfigured;
    rule.provenance.verification = icf::model::VerificationState::Verified;
    message.policy = rule;
    icf::Result<icf::wire::AdminResultMessage> applied = admin(message);
    if (!applied || applied.value().outcome != icf::Outcome::Ok) {
      std::fprintf(stderr, "bench: policy bootstrap failed\n");
      std::exit(1);
    }
  }
  {
    icf::wire::AdminMessage message;
    message.action = icf::wire::AdminAction::UpsertLink;
    icf::model::LinkRecord link;
    link.id = icf::EdgeId::parse("bench-edge").value();
    link.a = icf::EndpointId::parse("bench-a-e0").value();
    link.b = icf::EndpointId::parse("bench-b-e0").value();
    link.kind = icf::model::LinkKind::LoopbackTcp;
    link.state = icf::model::LinkState::Up;
    link.capacity = icf::CapacityUnits(100000);
    link.provenance.source = icf::model::EvidenceSource::AdminConfigured;
    link.provenance.verification = icf::model::VerificationState::Verified;
    message.link = link;
    icf::Result<icf::wire::AdminResultMessage> applied = admin(message);
    if (!applied || applied.value().outcome != icf::Outcome::Ok) {
      std::fprintf(stderr, "bench: link bootstrap failed\n");
      std::exit(1);
    }
  }
  {
    icf::wire::AdminMessage message;
    message.action = icf::wire::AdminAction::UpsertPath;
    icf::model::PathRecord path;
    path.id = icf::PathId::parse("bench-path").value();
    path.a = icf::EndpointId::parse("bench-a-e0").value();
    path.b = icf::EndpointId::parse("bench-b-e0").value();
    path.hops.push_back(icf::EdgeId::parse("bench-edge").value());
    path.provenance.source = icf::model::EvidenceSource::DerivedFromTopology;
    path.provenance.verification = icf::model::VerificationState::Verified;
    message.path = path;
    icf::Result<icf::wire::AdminResultMessage> applied = admin(message);
    if (!applied || applied.value().outcome != icf::Outcome::Ok) {
      std::fprintf(stderr, "bench: path bootstrap failed\n");
      std::exit(1);
    }
  }

  Latencies latencies;
  std::size_t committed = 0;
  Stopwatch watch;
  for (std::uint64_t index = 0; index < iterations; ++index) {
    Stopwatch single;
    icf::wire::AdminMessage propose;
    propose.action = icf::wire::AdminAction::AuthorizeContract;
    propose.cluster_id = icf::ClusterId::parse("bench-a").value();
    propose.cluster_b = icf::ClusterId::parse("bench-b").value();
    propose.endpoint = icf::EndpointId::parse("bench-a-e0").value();
    propose.endpoint_b = icf::EndpointId::parse("bench-b-e0").value();
    propose.capacity = icf::CapacityUnits(10);
    propose.lease_duration = icf::Duration::from_seconds(60);
    icf::Result<icf::wire::AdminResultMessage> proposed = admin(propose);
    if (!proposed || proposed.value().outcome != icf::Outcome::Ok) {
      std::fprintf(stderr, "bench: propose failed: %s\n",
                   proposed ? proposed.value().detail.c_str() : proposed.status().message().c_str());
      std::exit(1);
    }
    const icf::ContractId contract = proposed.value().contract;
    if (contract.is_nil()) {
      std::fprintf(stderr, "bench: the coordinator reported no contract identity\n");
      std::exit(1);
    }
    const auto consent_deadline = Clock::now() + std::chrono::seconds(20);
    bool consented = false;
    while (Clock::now() < consent_deadline) {
      icf::wire::QueryMessage contract_query;
      contract_query.kind = icf::wire::QueryKind::ShowContract;
      contract_query.contract = contract;
      icf::Result<icf::wire::QueryResultMessage> record = query(contract_query);
      if (record && !record.value().contracts.empty()) {
        const icf::model::ContractState state = record.value().contracts.front().state;
        if (state == icf::model::ContractState::Consented || state == icf::model::ContractState::Active) {
          consented = true;
          break;
        }
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!consented) {
      std::fprintf(stderr, "bench: the two cluster agents did not consent to the contract\n");
      std::exit(1);
    }
    icf::wire::AdminMessage issue;
    issue.action = icf::wire::AdminAction::IssueGrant;
    issue.contract = contract;
    issue.capacity = icf::CapacityUnits(10);
    icf::Result<icf::wire::AdminResultMessage> issued = admin(issue);
    if (!issued || issued.value().outcome != icf::Outcome::Ok) {
      std::fprintf(stderr, "bench: issue failed: %s\n",
                   issued ? issued.value().detail.c_str() : issued.status().message().c_str());
      std::exit(1);
    }
    const icf::GrantId grant = issued.value().grant;
    const auto commit_deadline = Clock::now() + std::chrono::seconds(20);
    bool active = false;
    while (Clock::now() < commit_deadline) {
      icf::wire::QueryMessage grant_query;
      grant_query.kind = icf::wire::QueryKind::ShowGrant;
      grant_query.grant = grant;
      icf::Result<icf::wire::QueryResultMessage> record = query(grant_query);
      if (record && !record.value().grants.empty() && record.value().grants.front().usable_state()) {
        active = true;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!active) {
      std::fprintf(stderr, "bench: the grant was never committed by both agents\n");
      std::exit(1);
    }
    latencies.add(single.elapsed_seconds() * 1e6);
    ++committed;
  }
  const double seconds = watch.elapsed_seconds();
  std::printf("flow   contract+grant     %10.2f flows/s  (mean %.1f ms, p99 %.1f ms per flow, %zu flows)\n",
              static_cast<double>(committed) / seconds, latencies.mean() / 1000.0, latencies.percentile(0.99) / 1000.0,
              committed);
  icf::wire::QueryMessage status_query;
  status_query.kind = icf::wire::QueryKind::Status;
  icf::Result<icf::wire::QueryResultMessage> status = query(status_query);
  if (status && status.value().status.has_value()) {
    std::printf("flow   coordinator state   grants=%zu contracts=%zu commits=%llu rejected_frames=%llu\n",
                status.value().status->grants, status.value().status->contracts,
                static_cast<unsigned long long>(status.value().status->commits),
                static_cast<unsigned long long>(status.value().status->rejected_frames));
  }

  coordinator.value()->stop();
  agent_a->stop();
  agent_b->stop();
  server.join();
  agent_a_thread.join();
  agent_b_thread.join();
  remove_tree(directory);
}

}  // namespace

int main(int argc, char** argv) {
  icf::Logger::instance().set_level(icf::LogLevel::Error);
  icf::Result<icf::app::Arguments> arguments = icf::app::parse_arguments(argc, argv);
  if (!arguments) {
    std::fprintf(stderr, "icf-bench: %s\n", arguments.status().message().c_str());
    return 2;
  }
  const bool quick = arguments.value().has("quick");
  const std::string only = arguments.value().get("scenario");
  const std::uint64_t codec_iterations = quick ? 20000 : 200000;
  const std::uint64_t store_iterations = quick ? 200 : 2000;
  const std::uint64_t engine_iterations = quick ? 20000 : 200000;
  const std::uint64_t rpc_iterations = quick ? 200 : 2000;
  const std::uint64_t flow_iterations = quick ? 10 : 50;

  std::printf("icf-bench %s  (%s profile)\n", ICF_VERSION_STRING, quick ? "quick" : "full");
  std::printf("---------\n");
  if (only.empty() || only == "codec") {
    bench_codec(codec_iterations);
  }
  if (only.empty() || only == "store") {
    bench_store(store_iterations, true);
  }
  if (only.empty() || only == "engine") {
    bench_engine(engine_iterations);
  }
  if (only.empty() || only == "rpc") {
    bench_rpc(rpc_iterations);
  }
  if (only.empty() || only == "flow") {
    bench_flow(flow_iterations);
  }
  std::printf("---------\n");
  return 0;
}
