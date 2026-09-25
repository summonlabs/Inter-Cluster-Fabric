#include "icf/runtime/agent.hpp"

#include <algorithm>
#include <fstream>
#include <utility>

#include "icf/core/limits.hpp"
#include "icf/core/log.hpp"
#include "icf/model/policy.hpp"
#include "icf/model/terms.hpp"
#include "icf/runtime/audit.hpp"
#include "icf/runtime/fencing.hpp"

namespace icf::runtime {
namespace {

constexpr std::uint64_t kControlConnectionBase = 1;
constexpr Duration kTickInterval = Duration::from_millis(250);

Digest content_digest_of(const model::ClusterRecord& record) {
  model::ClusterRecord copy = record;
  copy.revision = Revision{};
  copy.provenance = model::Provenance{};
  copy.incarnation_changes = 0;
  copy.generation_conflict = false;
  copy.conflicting_generation.reset();
  copy.content_digest = Digest{};
  copy.last_seen = Timestamp{};
  copy.consent_withdrawn = false;
  ByteWriter writer;
  model::encode_cluster(copy, writer);
  return Sha256::hash(writer.data());
}

}  // namespace

Agent::Agent(Config config, const Clock& clock)
    : config_(std::move(config)),
      clock_(&clock),
      loop_(clock),
      backoff_(config_.reconnect_backoff),
      rng_(entropy_seed()) {}

Agent::~Agent() = default;

Result<std::unique_ptr<Agent>> Agent::create(Config config, const Clock& clock) {
  if (config.cluster.empty()) {
    return invalid("the agent requires a cluster identity");
  }
  if (config.domain.empty()) {
    return invalid("the agent requires an authority domain identity");
  }
  if (config.state_directory.empty()) {
    return invalid("the agent requires a state directory");
  }
  if (config.coordinator_port == 0) {
    return invalid("the agent requires the coordinator's port");
  }
  auto agent = std::unique_ptr<Agent>(new Agent(std::move(config), clock));
  const Status started = agent->start();
  if (!started) {
    return started;
  }
  return agent;
}

Status Agent::load_state() {
  store::DurableStore::Options options;
  options.directory = config_.state_directory;
  options.snapshot_name = "agent.snapshot";
  options.wal_name = "agent.wal";
  options.compact_bytes = config_.compact_bytes;
  options.compact_records = config_.compact_records;
  options.durable = config_.durable;

  Result<store::DurableStore> opened = store::DurableStore::open(options, recovery_);
  if (!opened) {
    return opened.status();
  }
  store_ = std::move(opened.value());
  registry_ = std::move(recovery_.registry);
  recovery_.registry = model::Registry{};
  return Status::ok();
}

Status Agent::begin_incarnation() {
  const Result<Term> next = recovery_.meta.term.next();
  term_ = next ? next.value() : Term(UINT64_MAX);
  incarnation_ = IncarnationId::random(rng_);
  generation_ = config_.generation;
  policy_generation_ = config_.policy_generation;
  cluster_state_ = config_.state;
  started_at_ = clock_->now();

  const model::ClusterRecord* previous = registry_.find_cluster(config_.cluster);
  if (previous != nullptr) {
    if (config_.generation < previous->generation) {
      return Status::make(Outcome::Stale,
                          "the configured generation is older than the generation recorded on disk");
    }
    if (config_.generation == previous->generation) {
      const Generation bumped = previous->generation.next().has_value() ? previous->generation.next().value()
                                                                       : previous->generation;
      generation_ = bumped;
    }
    cluster_state_ = previous->state == model::ClusterState::Unknown ? config_.state : previous->state;
    if (config_.policy_generation < previous->policy_generation) {
      policy_generation_ = previous->policy_generation;
    }
    consent_withdrawn_ = previous->consent_withdrawn;
  }

  const Result<Sequence> meta = store_.append_meta(
      store::StoreMeta{term_, incarnation_, recovery_.meta.revision, store_.last_sequence(), started_at_,
                       recovery_.meta.truncations, registry_.digest()},
      started_at_);
  if (!meta) {
    return meta.status();
  }

  if (recovery_.recovered_from_store) {
    // Enforcement recovered from disk is historical: the coordinator has not revalidated it under
    // this incarnation, so nothing recovered may authorize connectivity.
    for (auto& entry : registry_.grants()) {
      model::GrantRecord& grant = entry.second;
      if (grant.state == model::GrantState::Active || grant.state == model::GrantState::Committed ||
          grant.state == model::GrantState::Prepared || grant.state == model::GrantState::Preparing ||
          grant.state == model::GrantState::Indeterminate) {
        grant.state = model::GrantState::Fenced;
        grant.note = "recovered enforcement is historical until the coordinator revalidates it";
        ++recovered_grants_fenced_;
        store::Mutation mutation;
        mutation.kind = store::MutationKind::GrantPut;
        mutation.grant = grant;
        const Status persisted = append_mutation(mutation);
        if (!persisted) {
          return persisted;
        }
      }
    }
    const Result<Sequence> incident = store_.append_incident(
        std::string("recovered from store: ") + std::to_string(recovered_grants_fenced_) +
            " enforcement records fenced pending revalidation",
        started_at_);
    if (!incident) {
      return incident.status();
    }
  }
  return append_audit("begin-incarnation", incarnation_.to_string(), Outcome::Ok,
                      std::string("term=") + std::to_string(term_.value()));
}

Status Agent::persist_cluster() {
  model::ClusterRecord record;
  const model::ClusterRecord* existing = registry_.find_cluster(config_.cluster);
  if (existing != nullptr) {
    record = *existing;
  }
  record.id = config_.cluster;
  record.domain = config_.domain;
  record.incarnation = incarnation_;
  record.generation = generation_;
  record.policy_generation = policy_generation_;
  record.state = cluster_state_;
  record.consent_withdrawn = consent_withdrawn_;
  record.last_seen = clock_->now();
  record.endpoints = config_.endpoints;
  for (model::EndpointRecord& endpoint : record.endpoints) {
    endpoint.cluster = config_.cluster;
    endpoint.policy_generation = policy_generation_;
  }
  std::sort(record.endpoints.begin(), record.endpoints.end(),
            [](const model::EndpointRecord& a, const model::EndpointRecord& b) { return a.id < b.id; });
  record.provenance.source = model::EvidenceSource::AdminConfigured;
  record.provenance.verification = model::VerificationState::Verified;
  record.provenance.observed_at = clock_->now();
  record.content_digest = content_digest_of(record);
  if (record.revision.increment()) {
    // revision advances so observers can order updates
  }
  const Status stored = registry_.put_cluster(record);
  if (!stored) {
    return stored;
  }
  store::Mutation mutation;
  mutation.kind = store::MutationKind::ClusterPut;
  mutation.cluster = *registry_.find_cluster(config_.cluster);
  return append_mutation(mutation);
}

Status Agent::start() {
  if (started_) {
    return Status::make(Outcome::AlreadyExists, "the agent is already started");
  }
  const Status loaded = load_state();
  if (!loaded) {
    return loaded;
  }
  const Status begun = begin_incarnation();
  if (!begun) {
    return begun;
  }
  const Status cluster = persist_cluster();
  if (!cluster) {
    return cluster;
  }
  const Status control = listen_control();
  if (!control) {
    return control;
  }
  const Timestamp now = clock_->now();
  (void)loop_.schedule(now, [this]() { tick(); });
  (void)loop_.schedule(now, [this]() {
    const Status connected = connect_to_coordinator();
    if (!connected) {
      ICF_LOG_WARN_KF("agent", "coordinator connection attempt failed",
                      (std::initializer_list<std::pair<std::string_view, std::string_view>>{
                          {"cluster", config_.cluster.c_str()},
                          {"outcome", ::icf::to_string(connected.outcome())}}));
    }
  });
  started_ = true;
  ICF_LOG_INFO_KF("agent", "agent started",
                  (std::initializer_list<std::pair<std::string_view, std::string_view>>{
                      {"cluster", config_.cluster.c_str()},
                      {"term", std::to_string(term_.value()).c_str()}}));
  return Status::ok();
}

Status Agent::listen_control() {
  std::uint16_t bound = 0;
  Result<net::TcpListener> listener =
      net::TcpListener::bind(config_.control_address, config_.control_port, 16, bound);
  if (!listener) {
    return listener.status();
  }
  control_listener_ = std::move(listener.value());
  control_port_ = bound;
  net::EventLoop::ListenerHandler handler = [this](net::Socket socket) -> Status {
    net::Connection::Config connection_config;
    connection_config.idle_deadline = Duration::from_seconds(60);
    Result<std::uint64_t> adopted =
        loop_.adopt(std::move(socket), std::move(connection_config),
                    [this](net::Connection& connection, const wire::Frame& frame) {
                      return handle_message(connection.id(), frame);
                    },
                    [this](net::Connection& connection, const Status&) { handle_disconnect(connection.id()); });
    if (!adopted) {
      return adopted.status();
    }
    Role role;
    role.connection_id = adopted.value();
    role.observer = true;
    roles_[adopted.value()] = role;
    return Status::ok();
  };
  const Status added = loop_.add_listener(std::move(control_listener_), std::move(handler));
  if (!added) {
    return added;
  }
  if (!config_.readiness_file.empty()) {
    std::ofstream ready(config_.readiness_file, std::ios::binary | std::ios::trunc);
    if (ready) {
      ready << "address=" << config_.control_address << "\n";
      ready << "port=" << control_port_ << "\n";
      ready << "cluster=" << config_.cluster.str() << "\n";
      ready << "incarnation=" << incarnation_.to_string() << "\n";
      ready << "generation=" << generation_.value() << "\n";
      ready << "term=" << term_.value() << "\n";
      ready.flush();
    }
  }
  return Status::ok();
}

Status Agent::serve() { return loop_.run(); }

void Agent::stop() noexcept { loop_.stop(); }

Status Agent::append_mutation(const store::Mutation& mutation) {
  const Result<Sequence> appended = store_.append(mutation, clock_->now());
  if (!appended) {
    return appended.status();
  }
  return Status::ok();
}

Status Agent::append_audit(std::string action, std::string subject, Outcome outcome, std::string detail) {
  if (registry_.audit().size() >= limits::kMaxAuditRecords) {
    return Status::ok();
  }
  const Status recorded = runtime::append_audit(registry_, clock_->now(), config_.cluster.str(), std::move(action),
                                                std::move(subject), outcome, std::move(detail));
  if (!recorded) {
    return recorded;
  }
  store::Mutation mutation;
  mutation.kind = store::MutationKind::AuditAppend;
  mutation.audit = registry_.audit().back();
  return append_mutation(mutation);
}

const model::ClusterRecord* Agent::local_cluster() const { return registry_.find_cluster(config_.cluster); }

std::vector<std::byte> Agent::channel_key() const {
  return std::vector<std::byte>(reinterpret_cast<const std::byte*>(config_.channel_key.data()),
                                reinterpret_cast<const std::byte*>(config_.channel_key.data()) +
                                    config_.channel_key.size());
}

Status Agent::connect_to_coordinator() {
  if (coordinator_connected_) {
    return Status::ok();
  }
  if (coordinator_connection_ != 0 && loop_.find(coordinator_connection_) != nullptr) {
    return Status::ok();
  }
  Result<net::Socket> socket = net::Socket::connect(config_.coordinator_host, config_.coordinator_port,
                                                    config_.connect_deadline, *clock_);
  if (!socket) {
    std::int64_t next = backoff_.nanos() * 2;
    if (next > config_.reconnect_backoff_max.nanos()) {
      next = config_.reconnect_backoff_max.nanos();
    }
    backoff_ = Duration::from_nanos(next);
    (void)loop_.schedule(clock_->now().plus(backoff_), [this]() { (void)connect_to_coordinator(); });
    return socket.status();
  }
  net::Connection::Config connection_config;
  connection_config.idle_deadline = Duration::from_millis(30000);
  // Verify inbound frames with the shared key from the first byte; the handshake is sent unsigned
  // and every frame after the acknowledgement is signed.
  connection_config.verify_key = channel_key();
  connection_config.sign_outbound = false;
  Result<std::uint64_t> adopted =
      loop_.adopt(std::move(socket.value()), std::move(connection_config),
                  [this](net::Connection& connection, const wire::Frame& frame) {
                    return handle_message(connection.id(), frame);
                  },
                  [this](net::Connection& connection, const Status&) { handle_disconnect(connection.id()); });
  if (!adopted) {
    return adopted.status();
  }
  coordinator_connection_ = adopted.value();
  handshake_complete_ = false;
  coordinator_connected_ = false;

  wire::HelloMessage hello;
  hello.role = wire::PeerRole::Agent;
  hello.cluster = config_.cluster;
  hello.domain = config_.domain;
  hello.incarnation = incarnation_;
  hello.generation = generation_;
  hello.policy_generation = policy_generation_;
  hello.agent_term = term_;
  hello.protocol_min = limits::kProtocolVersionMin;
  hello.protocol_max = limits::kProtocolVersionMax;
  hello.capabilities = wire::kCapabilityAll;
  const model::ClusterRecord* cluster = local_cluster();
  hello.content_digest = cluster == nullptr ? Digest{} : cluster->content_digest;
  hello.started_at = started_at_;
  const Status sent = send_message(wire::MessageType::Hello, hello);
  if (!sent) {
    return sent;
  }
  (void)loop_.schedule(clock_->now().plus(config_.handshake_deadline), [this]() {
    if (!handshake_complete_ && coordinator_connection_ != 0) {
      net::Connection* connection = loop_.find(coordinator_connection_);
      if (connection != nullptr) {
        connection->close(Status::make(Outcome::Unreachable, "the handshake deadline expired"));
      }
    }
  });
  return Status::ok();
}

template <class Message>
Status Agent::send_message(wire::MessageType type, const Message& message) {
  if (coordinator_connection_ == 0) {
    return Status::make(Outcome::Unreachable, "the coordinator connection is not established");
  }
  net::Connection* connection = loop_.find(coordinator_connection_);
  if (connection == nullptr) {
    return Status::make(Outcome::Unreachable, "the coordinator connection is gone");
  }
  Result<std::vector<std::byte>> payload = wire::encode_message(message);
  if (!payload) {
    return payload.status();
  }
  return connection->queue_frame(type, payload.value(), connection->signing_enabled());
}

Status Agent::send_to_coordinator(wire::MessageType type, const std::vector<std::byte>& payload) {
  net::Connection* connection = loop_.find(coordinator_connection_);
  if (connection == nullptr) {
    return Status::make(Outcome::Unreachable, "the coordinator connection is gone");
  }
  return connection->queue_frame(type, payload, connection->signing_enabled());
}

Status Agent::report_cluster() {
  const model::ClusterRecord* cluster = local_cluster();
  if (cluster == nullptr) {
    return Status::make(Outcome::Internal, "the agent has no local cluster record");
  }
  wire::ReportClusterMessage report;
  report.session = coordinator_session_;
  report.cluster = *cluster;
  return send_message(wire::MessageType::ReportCluster, report);
}

bool Agent::grant_enforceable(const model::GrantRecord& grant) const {
  if (grant.state != model::GrantState::Active) {
    return false;
  }
  if (!config_.require_coordinator) {
    return true;
  }
  const model::ContractRecord* contract = registry_.find_contract(grant.contract);
  if (contract == nullptr) {
    return false;
  }
  int side = -1;
  for (std::size_t index = 0; index < contract->parties.size(); ++index) {
    if (contract->parties[index].cluster == config_.cluster) {
      side = static_cast<int>(index);
    }
  }
  if (side < 0) {
    return false;
  }
  if (grant.incarnations[static_cast<std::size_t>(side)] != incarnation_ ||
      grant.generations[static_cast<std::size_t>(side)] != generation_ ||
      grant.policies[static_cast<std::size_t>(side)] != policy_generation_) {
    return false;
  }
  if (grant.coordinator_term != coordinator_term_) {
    return false;
  }
  if (clock_->now().unix_nanos() > grant.valid_until.unix_nanos()) {
    return false;
  }
  if (consent_withdrawn_ || cluster_state_ != model::ClusterState::Active) {
    return false;
  }
  return true;
}

Outcome Agent::local_enforcement_outcome(const GrantId& grant) const {
  const model::GrantRecord* record = registry_.find_grant(grant);
  if (record == nullptr) {
    return Outcome::NotFound;
  }
  if (record->state == model::GrantState::Fenced) {
    return Outcome::Fenced;
  }
  if (record->state == model::GrantState::Aborted) {
    return Outcome::Cancelled;
  }
  if (record->state == model::GrantState::Expired) {
    return Outcome::Expired;
  }
  if (!grant_enforceable(*record)) {
    if (clock_->now().unix_nanos() > record->valid_until.unix_nanos()) {
      return Outcome::Expired;
    }
    if (record->coordinator_term != coordinator_term_) {
      return Outcome::Fenced;
    }
    return Outcome::Stale;
  }
  return Outcome::Ok;
}

std::size_t Agent::enforced_grant_count() const {
  std::size_t count = 0;
  for (const auto& entry : registry_.grants()) {
    if (grant_enforceable(entry.second)) {
      ++count;
    }
  }
  return count;
}

Status Agent::fence_not_revalidated(Term coordinator_term) {
  std::size_t fenced = 0;
  for (auto& entry : registry_.grants()) {
    model::GrantRecord& grant = entry.second;
    if (grant.state != model::GrantState::Active && grant.state != model::GrantState::Committed &&
        grant.state != model::GrantState::Indeterminate && grant.state != model::GrantState::Prepared) {
      continue;
    }
    if (grant.coordinator_term == coordinator_term) {
      continue;
    }
    grant.state = model::GrantState::Fenced;
    grant.note = "the coordinator established a new authority term; this grant was not revalidated";
    ++fenced;
    ++fences_;
    store::Mutation mutation;
    mutation.kind = store::MutationKind::GrantPut;
    mutation.grant = grant;
    const Status persisted = append_mutation(mutation);
    if (!persisted) {
      return persisted;
    }
  }
  if (fenced > 0) {
    return append_audit("fence-term-change", incarnation_.to_string(), Outcome::Fenced,
                        std::to_string(fenced) + " grants fenced under the previous authority term");
  }
  return Status::ok();
}

Status Agent::reevaluate_enforcement(const std::string& reason) {
  const Timestamp now = clock_->now();
  for (auto& entry : registry_.grants()) {
    model::GrantRecord& grant = entry.second;
    if (grant.state != model::GrantState::Active && grant.state != model::GrantState::Committed) {
      continue;
    }
    if (now.unix_nanos() > grant.valid_until.unix_nanos()) {
      grant.state = model::GrantState::Expired;
      grant.note = "the lease elapsed";
      ++fences_;
      store::Mutation mutation;
      mutation.kind = store::MutationKind::GrantPut;
      mutation.grant = grant;
      const Status persisted = append_mutation(mutation);
      if (!persisted) {
        return persisted;
      }
      continue;
    }
    if (grant.state == model::GrantState::Committed && grant_enforceable(grant)) {
      grant.state = model::GrantState::Active;
      store::Mutation mutation;
      mutation.kind = store::MutationKind::GrantPut;
      mutation.grant = grant;
      const Status persisted = append_mutation(mutation);
      if (!persisted) {
        return persisted;
      }
      ++enforced_;
      continue;
    }
    if (grant.state == model::GrantState::Active && !grant_enforceable(grant)) {
      grant.state = model::GrantState::Fenced;
      grant.note = reason;
      ++fences_;
      store::Mutation mutation;
      mutation.kind = store::MutationKind::GrantPut;
      mutation.grant = grant;
      const Status persisted = append_mutation(mutation);
      if (!persisted) {
        return persisted;
      }
    }
  }
  return Status::ok();
}

namespace {
Digest enforcement_digest_of(const model::GrantRecord& grant) {
  ByteWriter writer;
  model::encode_grant(grant, writer);
  return Sha256::hash(writer.data());
}
}  // namespace

Status Agent::send_error_to(std::uint64_t connection_id, const Uuid& request, Outcome outcome,
                            const std::string& detail) {
  wire::ErrorMessage message;
  message.request = request;
  message.outcome = outcome;
  message.detail = detail;
  net::Connection* connection = loop_.find(connection_id);
  if (connection == nullptr) {
    return Status::ok();
  }
  Result<std::vector<std::byte>> payload = wire::encode_message(message);
  if (!payload) {
    return payload.status();
  }
  return connection->queue_frame(wire::MessageType::Error, payload.value(), connection->signing_enabled());
}

Status Agent::handle_message(std::uint64_t connection_id, const wire::Frame& frame) {
  const bool from_coordinator = connection_id == coordinator_connection_;
  {
    const auto it = roles_.find(connection_id);
    if (it != roles_.end() && !from_coordinator && frame.header.type == wire::MessageType::Hello) {
      return on_control_hello(connection_id, frame);
    }
  }
  if (from_coordinator) {
    switch (frame.header.type) {
      case wire::MessageType::HelloAck:
        return on_hello_ack(frame);
      case wire::MessageType::ReportAck:
        return on_report_ack(frame);
      case wire::MessageType::ProposeContract:
        return on_propose_contract(frame);
      case wire::MessageType::PrepareGrant:
        return on_prepare_grant(frame);
      case wire::MessageType::CommitGrant:
        return on_commit_grant(frame);
      case wire::MessageType::AbortGrant:
        return on_abort_grant(frame);
      case wire::MessageType::Fence:
        return on_fence(frame);
      case wire::MessageType::StatusRequest:
        return on_status_request(frame);
      case wire::MessageType::Ping:
        return on_ping(frame);
      case wire::MessageType::Pong:
        // Keep-alive reply: nothing to answer.
        return Status::ok();
      case wire::MessageType::Error:
        // The coordinator reports a problem it already observed; replying would loop forever.
        ++errors_received_;
        return Status::ok();
      default:
        ++rejected_frames_;
        return send_error_to(connection_id, Uuid{}, Outcome::Unsupported,
                             std::string("message type is not accepted from the coordinator: ") +
                                 wire::to_string(frame.header.type));
    }
  }
  switch (frame.header.type) {
    case wire::MessageType::Hello:
      return on_control_hello(connection_id, frame);
    case wire::MessageType::Query:
      return on_query(connection_id, frame);
    case wire::MessageType::Admin:
      return on_admin(connection_id, frame);
    case wire::MessageType::Ping:
      return on_ping(frame);
    case wire::MessageType::Pong:
      return Status::ok();
    case wire::MessageType::Error:
      ++errors_received_;
      return Status::ok();
    default:
      ++rejected_frames_;
      return send_error_to(connection_id, Uuid{}, Outcome::Unauthorized,
                           "the local control channel accepts only queries and local administration");
  }
}

void Agent::handle_disconnect(std::uint64_t connection_id) {
  roles_.erase(connection_id);
  if (connection_id != coordinator_connection_) {
    return;
  }
  coordinator_connected_ = false;
  handshake_complete_ = false;
  coordinator_connection_ = 0;
  ICF_LOG_WARN_KF("agent", "coordinator connection lost",
                  (std::initializer_list<std::pair<std::string_view, std::string_view>>{
                      {"cluster", config_.cluster.c_str()}}));
  // Enforcement stays in force until the lease elapses; a fresh handshake revalidates it under
  // the coordinator's current term.
  (void)loop_.schedule(clock_->now().plus(backoff_), [this]() {
    connect_scheduled_ = false;
    const Status reconnected = connect_to_coordinator();
    if (!reconnected) {
      ICF_LOG_DEBUG("agent", "reconnect attempt failed; another attempt is scheduled");
    }
  });
  connect_scheduled_ = true;
}

Status Agent::on_control_hello(std::uint64_t connection_id, const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::HelloMessage> hello = wire::decode_hello(reader);
  if (!hello) {
    ++rejected_frames_;
    return send_error_to(connection_id, Uuid{}, hello.status().outcome(), hello.status().message());
  }
  wire::HelloAckMessage ack;
  ack.coordinator = incarnation_;
  ack.coordinator_term = term_;
  ack.view_digest = registry_.digest();
  if (hello.value().role != wire::PeerRole::Observer) {
    ack.outcome = Outcome::Unauthorized;
    ack.detail = "the local control channel accepts observer sessions only";
    ++refusals_;
    net::Connection* connection = loop_.find(connection_id);
    if (connection != nullptr) {
      Result<std::vector<std::byte>> payload = wire::encode_message(ack);
      if (payload) {
        (void)connection->queue_frame(wire::MessageType::HelloAck, payload.value(), connection->signing_enabled());
      }
    }
    return Status::ok();
  }
  Role role;
  role.observer = true;
  role.hello_complete = true;
  role.token = SessionToken::random(rng_);
  role.connection_id = connection_id;
  roles_[connection_id] = role;
  ack.session = role.token;
  ack.outcome = Outcome::Ok;
  ack.negotiated_version = limits::kProtocolVersionMax;
  ack.detail = "local control session established";
  net::Connection* connection = loop_.find(connection_id);
  if (connection == nullptr) {
    return Status::ok();
  }
  Result<std::vector<std::byte>> payload = wire::encode_message(ack);
  if (!payload) {
    return payload.status();
  }
  return connection->queue_frame(wire::MessageType::HelloAck, payload.value(), connection->signing_enabled());
}

Status Agent::on_hello_ack(const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::HelloAckMessage> ack = wire::decode_hello_ack(reader);
  if (!ack) {
    ++rejected_frames_;
    return ack.status();
  }
  if (ack.value().outcome != Outcome::Ok) {
    ++refusals_;
    ICF_LOG_WARN_KF("agent", "coordinator refused the handshake",
                    (std::initializer_list<std::pair<std::string_view, std::string_view>>{
                        {"cluster", config_.cluster.c_str()},
                        {"outcome", ::icf::to_string(ack.value().outcome)},
                        {"detail", ack.value().detail}}));
    net::Connection* connection = loop_.find(coordinator_connection_);
    if (connection != nullptr) {
      connection->close(Status::make(ack.value().outcome, ack.value().detail));
    }
    return Status::ok();
  }
  if (net::Connection* connection = loop_.find(coordinator_connection_); connection != nullptr) {
    connection->enable_outbound_signing();
  }
  coordinator_session_ = ack.value().session;
  coordinator_term_ = ack.value().coordinator_term;
  coordinator_incarnation_ = ack.value().coordinator;
  handshake_complete_ = true;
  coordinator_connected_ = true;
  backoff_ = config_.reconnect_backoff;
  const Status fenced = fence_not_revalidated(coordinator_term_);
  if (!fenced) {
    return fenced;
  }
  return report_cluster();
}

Status Agent::on_report_ack(const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::ReportAckMessage> ack = wire::decode_report_ack(reader);
  if (!ack) {
    ++rejected_frames_;
    return ack.status();
  }
  if (ack.value().outcome != Outcome::Ok) {
    ++refusals_;
    ICF_LOG_WARN_KF("agent", "cluster report was not accepted",
                    (std::initializer_list<std::pair<std::string_view, std::string_view>>{
                        {"cluster", config_.cluster.c_str()},
                        {"outcome", ::icf::to_string(ack.value().outcome)}}));
  }
  return Status::ok();
}

Status Agent::on_propose_contract(const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::ProposeContractMessage> proposal = wire::decode_propose_contract(reader);
  if (!proposal) {
    ++rejected_frames_;
    return proposal.status();
  }
  const model::ContractTerms& terms = proposal.value().terms;
  int side = -1;
  for (std::size_t index = 0; index < terms.parties.size(); ++index) {
    if (terms.parties[index].cluster == config_.cluster) {
      side = static_cast<int>(index);
    }
  }
  wire::ContractConsentMessage consent;
  consent.session = coordinator_session_;
  consent.contract = proposal.value().contract;
  consent.terms_digest = terms.digest();
  consent.incarnation = incarnation_;
  consent.generation = generation_;
  consent.policy_generation = policy_generation_;
  consent.agent_term = term_;
  consent.decision = model::ConsentDecision::Refused;

  if (side < 0) {
    consent.reason = "the terms do not name this cluster";
    ++refusals_;
    return send_message(wire::MessageType::ContractConsent, consent);
  }
  const std::size_t index = static_cast<std::size_t>(side);
  consent.endpoint = terms.parties[index].endpoint;
  if (terms.incarnations[index] != incarnation_) {
    consent.reason = "the terms are bound to a superseded incarnation";
    ++refusals_;
    return send_message(wire::MessageType::ContractConsent, consent);
  }
  if (terms.generations[index] != generation_) {
    consent.reason = "the terms are bound to a superseded generation";
    ++refusals_;
    return send_message(wire::MessageType::ContractConsent, consent);
  }
  if (terms.policies[index] != policy_generation_) {
    consent.reason = "the terms are bound to a superseded policy generation";
    ++refusals_;
    return send_message(wire::MessageType::ContractConsent, consent);
  }
  if (consent_withdrawn_) {
    consent.reason = "this cluster has withdrawn consent";
    ++refusals_;
    return send_message(wire::MessageType::ContractConsent, consent);
  }
  if (cluster_state_ != model::ClusterState::Active) {
    consent.reason = "this cluster is not in the active state";
    ++refusals_;
    return send_message(wire::MessageType::ContractConsent, consent);
  }
  const model::ClusterRecord* cluster = local_cluster();
  const model::EndpointRecord* endpoint = nullptr;
  if (cluster != nullptr) {
    for (const model::EndpointRecord& candidate : cluster->endpoints) {
      if (candidate.id == terms.parties[index].endpoint) {
        endpoint = &candidate;
        break;
      }
    }
  }
  if (endpoint == nullptr) {
    consent.reason = "the terms name an endpoint scope this cluster does not own";
    ++refusals_;
    return send_message(wire::MessageType::ContractConsent, consent);
  }
  if (!endpoint->inter_cluster_allowed || endpoint->state != model::EndpointState::Active) {
    consent.reason = "the endpoint scope does not accept inter-cluster connectivity";
    ++refusals_;
    return send_message(wire::MessageType::ContractConsent, consent);
  }
  const Status valid = terms.validate();
  if (!valid) {
    consent.reason = valid.message();
    ++refusals_;
    return send_message(wire::MessageType::ContractConsent, consent);
  }

  consent.decision = model::ConsentDecision::Accepted;
  consent.reason = "terms accepted by the cluster agent";

  model::ContractRecord contract;
  const model::ContractRecord* existing = registry_.find_contract(proposal.value().contract);
  if (existing != nullptr) {
    contract = *existing;
  }
  contract.id = proposal.value().contract;
  contract.parties = terms.parties;
  contract.capacity = terms.capacity;
  contract.lease_duration = terms.lease_duration;
  contract.terms_digest = consent.terms_digest;
  contract.created_at = contract.created_at.is_zero() ? clock_->now() : contract.created_at;
  contract.updated_at = clock_->now();
  contract.state = model::ContractState::AwaitingConsent;
  contract.provenance.source = model::EvidenceSource::AgentReported;
  contract.provenance.verification = model::VerificationState::Verified;
  contract.provenance.observed_at = clock_->now();
  model::ConsentRecord record;
  record.cluster = config_.cluster;
  record.endpoint = consent.endpoint;
  record.incarnation = incarnation_;
  record.generation = generation_;
  record.policy_generation = policy_generation_;
  record.agent_term = term_;
  record.terms_digest = consent.terms_digest;
  record.decision = model::ConsentDecision::Accepted;
  record.decided_at = clock_->now();
  record.session = coordinator_session_;
  record.authenticity = config_.channel_key.empty() ? model::TransportAuthenticity::None
                                                    : model::TransportAuthenticity::SharedKeyMac;
  record.reason = consent.reason;
  contract.consents[index] = record;
  if (contract.revision.increment()) {
    // revision advances so ordering is observable
  }
  const Status stored = registry_.put_contract(contract);
  if (!stored) {
    return stored;
  }
  store::Mutation mutation;
  mutation.kind = store::MutationKind::ContractPut;
  mutation.contract = contract;
  const Status persisted = append_mutation(mutation);
  if (!persisted) {
    return persisted;
  }
  const Status audited = append_audit("consent", contract.id.to_string(), Outcome::Ok,
                                      "terms accepted and bound to this incarnation and generation");
  if (!audited) {
    return audited;
  }
  return send_message(wire::MessageType::ContractConsent, consent);
}

Status Agent::on_prepare_grant(const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::PrepareGrantMessage> message = wire::decode_prepare_grant(reader);
  if (!message) {
    ++rejected_frames_;
    return message.status();
  }
  const model::GrantRecord& incoming = message.value().grant;
  wire::GrantPreparedMessage response;
  response.session = coordinator_session_;
  response.grant = incoming.id;
  response.attempt = incoming.attempt;
  response.agent_term = term_;
  response.accepted = false;

  const model::ContractRecord* contract = registry_.find_contract(incoming.contract);
  if (contract == nullptr) {
    response.detail = "no local record of the contract this grant names";
    ++refusals_;
    return send_message(wire::MessageType::GrantPrepared, response);
  }
  int side = -1;
  for (std::size_t index = 0; index < contract->parties.size(); ++index) {
    if (contract->parties[index].cluster == config_.cluster) {
      side = static_cast<int>(index);
    }
  }
  if (side < 0) {
    response.detail = "the grant does not involve this cluster";
    ++refusals_;
    return send_message(wire::MessageType::GrantPrepared, response);
  }
  const std::size_t index = static_cast<std::size_t>(side);
  if (!contract->consents[index].has_value() ||
      contract->consents[index]->decision != model::ConsentDecision::Accepted) {
    response.detail = "this cluster has not consented to the contract";
    ++refusals_;
    return send_message(wire::MessageType::GrantPrepared, response);
  }
  if (contract->consents[index]->terms_digest != incoming.terms_digest ||
      contract->terms_digest != incoming.terms_digest) {
    response.detail = "the grant does not cover the terms this cluster consented to";
    ++refusals_;
    return send_message(wire::MessageType::GrantPrepared, response);
  }
  if (incoming.incarnations[index] != incarnation_ || incoming.generations[index] != generation_ ||
      incoming.policies[index] != policy_generation_) {
    response.detail = "the grant is bound to a superseded incarnation, generation, or policy generation";
    ++refusals_;
    return send_message(wire::MessageType::GrantPrepared, response);
  }
  if (incoming.coordinator_term != coordinator_term_) {
    response.detail = "the grant was issued under a superseded coordinator term";
    ++refusals_;
    return send_message(wire::MessageType::GrantPrepared, response);
  }
  const model::ClusterRecord* cluster = local_cluster();
  const model::EndpointRecord* endpoint = nullptr;
  if (cluster != nullptr) {
    for (const model::EndpointRecord& candidate : cluster->endpoints) {
      if (candidate.id == contract->parties[index].endpoint) {
        endpoint = &candidate;
        break;
      }
    }
  }
  if (endpoint == nullptr) {
    response.detail = "the grant names an endpoint scope this cluster does not own";
    ++refusals_;
    return send_message(wire::MessageType::GrantPrepared, response);
  }
  if (incoming.capacity.value() > endpoint->capacity.value()) {
    response.detail = "the granted capacity exceeds the declared endpoint capacity";
    ++refusals_;
    return send_message(wire::MessageType::GrantPrepared, response);
  }

  model::GrantRecord grant = incoming;
  grant.state = model::GrantState::Prepared;
  grant.note = "prepared by the cluster agent; waiting for the coordinator commit";
  grant.provenance.source = model::EvidenceSource::AgentReported;
  grant.provenance.verification = model::VerificationState::Verified;
  grant.provenance.observed_at = clock_->now();
  const Status stored = registry_.put_grant(grant);
  if (!stored) {
    response.detail = stored.message();
    return send_message(wire::MessageType::GrantPrepared, response);
  }
  store::Mutation mutation;
  mutation.kind = store::MutationKind::GrantPut;
  mutation.grant = grant;
  const Status persisted = append_mutation(mutation);
  if (!persisted) {
    return persisted;
  }
  const model::GrantRecord* stored_grant = registry_.find_grant(grant.id);
  response.accepted = true;
  response.detail = "prepared";
  response.enforcement_digest = enforcement_digest_of(*stored_grant);
  return send_message(wire::MessageType::GrantPrepared, response);
}

Status Agent::on_commit_grant(const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::CommitGrantMessage> message = wire::decode_commit_grant(reader);
  if (!message) {
    ++rejected_frames_;
    return message.status();
  }
  wire::GrantCommittedMessage response;
  response.session = coordinator_session_;
  response.grant = message.value().grant;
  response.attempt = message.value().attempt;
  response.agent_term = term_;
  response.installed = false;
  model::GrantRecord* grant = registry_.find_grant(message.value().grant);
  if (grant == nullptr) {
    response.detail = "the grant is not recorded locally";
    ++refusals_;
    return send_message(wire::MessageType::GrantCommitted, response);
  }
  if (grant->attempt != message.value().attempt) {
    response.detail = "the commit names a different attempt than the prepared one";
    return send_message(wire::MessageType::GrantCommitted, response);
  }
  if (grant->state != model::GrantState::Prepared && grant->state != model::GrantState::Active) {
    response.detail = std::string("the grant is in state ") + model::to_string(grant->state) +
                      " and cannot be committed";
    return send_message(wire::MessageType::GrantCommitted, response);
  }
  grant->state = model::GrantState::Active;
  grant->note = "enforced by the cluster agent";
  grant->provenance.observed_at = clock_->now();
  store::Mutation mutation;
  mutation.kind = store::MutationKind::GrantPut;
  mutation.grant = *grant;
  const Status persisted = append_mutation(mutation);
  if (!persisted) {
    return persisted;
  }
  response.installed = true;
  response.detail = "enforced";
  response.enforcement_digest = enforcement_digest_of(*grant);
  const Status audited = append_audit("commit-grant", grant->id.to_string(), Outcome::Ok,
                                      "the exact attempt the coordinator prepared is now enforced");
  if (!audited) {
    return audited;
  }
  return send_message(wire::MessageType::GrantCommitted, response);
}

Status Agent::on_abort_grant(const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::AbortGrantMessage> message = wire::decode_abort_grant(reader);
  if (!message) {
    ++rejected_frames_;
    return message.status();
  }
  if (model::GrantRecord* grant = registry_.find_grant(message.value().grant); grant != nullptr) {
    grant->state = model::GrantState::Aborted;
    grant->note = message.value().reason;
    store::Mutation mutation;
    mutation.kind = store::MutationKind::GrantPut;
    mutation.grant = *grant;
    const Status persisted = append_mutation(mutation);
    if (!persisted) {
      return persisted;
    }
  }
  wire::GrantAbortedMessage response;
  response.session = coordinator_session_;
  response.grant = message.value().grant;
  response.attempt = message.value().attempt;
  response.reason = message.value().reason;
  return send_message(wire::MessageType::GrantAborted, response);
}

Status Agent::on_fence(const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::FenceMessage> message = wire::decode_fence(reader);
  if (!message) {
    ++rejected_frames_;
    return message.status();
  }
  wire::FenceAckMessage ack;
  ack.session = coordinator_session_;
  for (const GrantId& grant_id : message.value().grants) {
    wire::FenceResult result;
    result.grant = grant_id;
    model::GrantRecord* grant = registry_.find_grant(grant_id);
    if (grant == nullptr) {
      result.outcome = Outcome::NotFound;
    } else if (grant->state == model::GrantState::Fenced) {
      result.outcome = Outcome::Fenced;
    } else {
      grant->state = model::GrantState::Fenced;
      grant->note = message.value().reason;
      store::Mutation mutation;
      mutation.kind = store::MutationKind::GrantPut;
      mutation.grant = *grant;
      const Status persisted = append_mutation(mutation);
      if (!persisted) {
        return persisted;
      }
      ++fences_;
      result.outcome = Outcome::Ok;
    }
    ack.results.push_back(result);
  }
  const Status audited = append_audit("fence-grants", incarnation_.to_string(), Outcome::Fenced,
                                      std::to_string(ack.results.size()) + " grants fenced on coordinator request");
  if (!audited) {
    return audited;
  }
  return send_message(wire::MessageType::FenceAck, ack);
}

Status Agent::on_status_request(const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::StatusRequestMessage> message = wire::decode_status_request(reader);
  if (!message) {
    ++rejected_frames_;
    return message.status();
  }
  wire::StatusReportMessage report;
  report.session = coordinator_session_;
  report.request = message.value().request;
  report.cluster = config_.cluster;
  report.incarnation = incarnation_;
  report.generation = generation_;
  report.policy_generation = policy_generation_;
  report.agent_term = term_;
  for (const auto& entry : registry_.grants()) {
    wire::GrantStatusEntry status;
    status.grant = entry.second.id;
    status.attempt = entry.second.attempt;
    status.state = entry.second.state;
    status.agent_term = entry.second.coordinator_term;
    status.enforcement_digest = entry.second.enforcement_digest[0];
    report.grants.push_back(status);
    if (report.grants.size() >= limits::kMaxGrants) {
      break;
    }
  }
  (void)revalidations_;
  return send_message(wire::MessageType::StatusReport, report);
}

Status Agent::on_ping(const wire::Frame& frame) {
  std::uint64_t sequence = 0;
  ByteReader reader(frame.payload);
  Result<wire::PingMessage> ping = wire::decode_ping(reader);
  if (ping) {
    sequence = ping.value().sequence.value();
  }
  wire::PongMessage pong;
  pong.sequence = Sequence(sequence);
  Result<std::vector<std::byte>> payload = wire::encode_message(pong);
  if (!payload) {
    return payload.status();
  }
  net::Connection* connection = loop_.find(frame.header.flags == 0 ? coordinator_connection_ : coordinator_connection_);
  if (connection == nullptr) {
    return Status::ok();
  }
  return connection->queue_frame(wire::MessageType::Pong, payload.value(), connection->signing_enabled());
}

Status Agent::on_query(std::uint64_t connection_id, const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::QueryMessage> query = wire::decode_query(reader);
  if (!query) {
    ++rejected_frames_;
    return send_error_to(connection_id, Uuid{}, query.status().outcome(), query.status().message());
  }
  wire::QueryResultMessage result;
  const Status handled = handle_query_local(query.value(), result);
  if (!handled) {
    result.outcome = handled.outcome();
    result.detail = handled.message();
  }
  net::Connection* connection = loop_.find(connection_id);
  if (connection == nullptr) {
    return Status::ok();
  }
  Result<std::vector<std::byte>> payload = wire::encode_message(result);
  if (!payload) {
    return payload.status();
  }
  return connection->queue_frame(wire::MessageType::QueryResult, payload.value(), connection->signing_enabled());
}

Status Agent::on_admin(std::uint64_t connection_id, const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::AdminMessage> request = wire::decode_admin(reader);
  if (!request) {
    ++rejected_frames_;
    return send_error_to(connection_id, Uuid{}, request.status().outcome(), request.status().message());
  }
  wire::AdminResultMessage result;
  const Status handled = update_from_admin(request.value(), result);
  if (!handled) {
    result.outcome = handled.outcome();
    if (result.detail.empty()) {
      result.detail = handled.message();
    }
  }
  result.request = request.value().request;
  result.view_digest = registry_.digest();
  net::Connection* connection = loop_.find(connection_id);
  if (connection == nullptr) {
    return Status::ok();
  }
  Result<std::vector<std::byte>> payload = wire::encode_message(result);
  if (!payload) {
    return payload.status();
  }
  return connection->queue_frame(wire::MessageType::AdminResult, payload.value(), connection->signing_enabled());
}

Status Agent::handle_query_local(const wire::QueryMessage& query, wire::QueryResultMessage& result) const {
  result.request = query.request;
  result.kind = query.kind;
  result.outcome = Outcome::Ok;
  const std::size_t limit = query.limit == 0 ? 256 : query.limit;
  switch (query.kind) {
    case wire::QueryKind::Status:
      result.status = status();
      break;
    case wire::QueryKind::ListClusters: {
      const model::ClusterRecord* cluster = local_cluster();
      if (cluster != nullptr) {
        result.clusters.push_back(*cluster);
      }
      break;
    }
    case wire::QueryKind::ListGrants: {
      for (const auto& entry : registry_.grants()) {
        if (result.grants.size() >= limit) {
          break;
        }
        result.grants.push_back(entry.second);
      }
      break;
    }
    case wire::QueryKind::ShowGrant: {
      const model::GrantRecord* grant = registry_.find_grant(query.grant);
      if (grant == nullptr) {
        return not_found("grant is not recorded locally");
      }
      result.grants.push_back(*grant);
      result.detail = std::string("local enforcement outcome: ") +
                      ::icf::to_string(local_enforcement_outcome(query.grant));
      break;
    }
    case wire::QueryKind::ListContracts: {
      for (const auto& entry : registry_.contracts()) {
        if (result.contracts.size() >= limit) {
          break;
        }
        result.contracts.push_back(entry.second);
      }
      break;
    }
    case wire::QueryKind::ShowContract: {
      const model::ContractRecord* contract = registry_.find_contract(query.contract);
      if (contract == nullptr) {
        return not_found("contract is not recorded locally");
      }
      result.contracts.push_back(*contract);
      break;
    }
    case wire::QueryKind::ListAudit: {
      const std::vector<model::AuditRecord>& trail = registry_.audit();
      const std::size_t take = trail.size() < limit ? trail.size() : limit;
      for (std::size_t index = trail.size() - take; index < trail.size(); ++index) {
        result.audit.push_back(trail[index]);
      }
      break;
    }
    default:
      return Status::make(Outcome::Unsupported,
                          "the local control channel answers status, cluster, grant, contract, and audit queries");
  }
  return Status::ok();
}

model::CoordinatorStatus Agent::status() const {
  model::CoordinatorStatus status;
  status.domain = config_.domain;
  status.incarnation = incarnation_;
  status.term = term_;
  status.started_at = started_at_;
  status.uptime_nanos = static_cast<std::uint64_t>(clock_->monotonic_nanos() < 0 ? 0 : clock_->monotonic_nanos());
  status.view_digest = registry_.digest();
  status.recovered_from_store = recovery_.recovered_from_store;
  status.recovered_records = recovery_.wal.records;
  status.truncations_recovered = recovery_.meta.truncations;
  const model::RegistryCounts counts = registry_.counts();
  status.clusters = counts.clusters;
  status.endpoints = counts.endpoints;
  status.links = 0;
  status.paths = 0;
  status.contracts = counts.contracts;
  status.grants = counts.grants;
  status.reservations = counts.reservations;
  status.policies = counts.policies;
  status.audit = counts.audit;
  status.connected_agents = coordinator_connected_ ? 1u : 0u;
  status.commits = enforced_;
  status.fences = fences_;
  status.refusals = refusals_;
  status.revalidations = revalidations_;
  status.rejected_replays = recovered_grants_fenced_;
  status.rejected_frames = rejected_frames_;
  status.store_path = store_.snapshot_path();
  return status;
}

Status Agent::set_cluster_state(model::ClusterState state) {
  cluster_state_ = state;
  const Status persisted = persist_cluster();
  if (!persisted) {
    return persisted;
  }
  const Status reevaluated = reevaluate_enforcement("the cluster left the active state");
  if (!reevaluated) {
    return reevaluated;
  }
  if (coordinator_connected_) {
    return report_cluster();
  }
  return Status::ok();
}

Status Agent::bump_generation(const std::string& reason) {
  const Result<Generation> next = generation_.next();
  if (!next) {
    return next.status();
  }
  generation_ = next.value();
  const Status fenced = fence_not_revalidated(term_);
  if (!fenced) {
    return fenced;
  }
  for (auto& entry : registry_.grants()) {
    model::GrantRecord& grant = entry.second;
    if (grant.state == model::GrantState::Active || grant.state == model::GrantState::Committed) {
      grant.state = model::GrantState::Fenced;
      grant.note = "the cluster generation advanced; the grant must be reissued";
      store::Mutation mutation;
      mutation.kind = store::MutationKind::GrantPut;
      mutation.grant = grant;
      const Status persisted = append_mutation(mutation);
      if (!persisted) {
        return persisted;
      }
    }
  }
  const Status persisted = persist_cluster();
  if (!persisted) {
    return persisted;
  }
  const Status audited = append_audit("bump-generation", config_.cluster.str(), Outcome::Ok, reason);
  if (!audited) {
    return audited;
  }
  if (coordinator_connected_) {
    return report_cluster();
  }
  return Status::ok();
}

Status Agent::set_policy_generation(PolicyGeneration generation) {
  if (generation < policy_generation_) {
    return Status::make(Outcome::Stale, "the policy generation must not move backwards");
  }
  policy_generation_ = generation;
  const Status persisted = persist_cluster();
  if (!persisted) {
    return persisted;
  }
  const Status reevaluated = reevaluate_enforcement("the policy generation changed");
  if (!reevaluated) {
    return reevaluated;
  }
  if (coordinator_connected_) {
    return report_cluster();
  }
  return Status::ok();
}

Status Agent::withdraw_consent(const std::string& reason) {
  consent_withdrawn_ = true;
  const Status persisted = persist_cluster();
  if (!persisted) {
    return persisted;
  }
  const Status reevaluated = reevaluate_enforcement("consent withdrawn by the cluster");
  if (!reevaluated) {
    return reevaluated;
  }
  if (coordinator_connected_) {
    wire::WithdrawMessage withdraw;
    withdraw.session = coordinator_session_;
    withdraw.cluster = config_.cluster;
    withdraw.incarnation = incarnation_;
    withdraw.generation = generation_;
    withdraw.reason = reason;
    const Status sent = send_message(wire::MessageType::Withdraw, withdraw);
    if (!sent) {
      return sent;
    }
  }
  return append_audit("withdraw-consent", config_.cluster.str(), Outcome::Fenced, reason);
}

Status Agent::fence_local_grant(const GrantId& grant, const std::string& reason) {
  model::GrantRecord* record = registry_.find_grant(grant);
  if (record == nullptr) {
    return not_found("the grant is not recorded locally");
  }
  record->state = model::GrantState::Fenced;
  record->note = reason;
  store::Mutation mutation;
  mutation.kind = store::MutationKind::GrantPut;
  mutation.grant = *record;
  const Status persisted = append_mutation(mutation);
  if (!persisted) {
    return persisted;
  }
  ++fences_;
  return append_audit("fence-local-grant", grant.to_string(), Outcome::Fenced, reason);
}

Status Agent::upsert_endpoint(model::EndpointRecord endpoint) {
  endpoint.cluster = config_.cluster;
  endpoint.policy_generation = policy_generation_;
  if (endpoint.state == model::EndpointState::Unknown) {
    endpoint.state = model::EndpointState::Active;
  }
  endpoint.provenance.source = model::EvidenceSource::AdminConfigured;
  endpoint.provenance.verification = model::VerificationState::Verified;
  endpoint.provenance.observed_at = clock_->now();
  bool replaced = false;
  for (model::EndpointRecord& candidate : config_.endpoints) {
    if (candidate.id == endpoint.id) {
      candidate = endpoint;
      replaced = true;
      break;
    }
  }
  if (!replaced) {
    if (config_.endpoints.size() >= limits::kMaxEndpointsPerCluster) {
      return Status::make(Outcome::CapacityExceeded, "the cluster declares too many endpoint scopes");
    }
    config_.endpoints.push_back(endpoint);
  }
  const Status persisted = persist_cluster();
  if (!persisted) {
    return persisted;
  }
  if (coordinator_connected_) {
    return report_cluster();
  }
  return Status::ok();
}

Status Agent::update_from_admin(const wire::AdminMessage& request, wire::AdminResultMessage& result) {
  result.request = request.request;
  result.outcome = Outcome::Ok;
  switch (request.action) {
    case wire::AdminAction::SetClusterState:
      return set_cluster_state(request.cluster_state);
    case wire::AdminAction::WithdrawConsent:
      return withdraw_consent(request.reason.empty() ? "operator request" : request.reason);
    case wire::AdminAction::RestoreConsent:
      consent_withdrawn_ = false;
      return persist_cluster();
    case wire::AdminAction::FenceGrant:
      return fence_local_grant(request.grant, request.reason.empty() ? "operator request" : request.reason);
    case wire::AdminAction::UpsertCluster: {
      if (!request.cluster.has_value()) {
        return invalid("upsert-cluster requires a cluster record");
      }
      for (const model::EndpointRecord& endpoint : request.cluster->endpoints) {
        const Status updated = upsert_endpoint(endpoint);
        if (!updated) {
          return updated;
        }
      }
      return Status::ok();
    }
    case wire::AdminAction::ReloadStore:
      result.outcome = Outcome::Unsupported;
      result.detail = "the store is opened during startup; restart the agent to reload it";
      return unsupported(result.detail);
    default:
      result.outcome = Outcome::Unsupported;
      result.detail = std::string("the local control channel does not accept action '") +
                      wire::to_string(request.action) + "'";
      return unsupported(result.detail);
  }
}

void Agent::tick() {
  if (!coordinator_connected_ && !connect_scheduled_) {
    const Status connected = connect_to_coordinator();
    if (!connected) {
      connect_scheduled_ = true;
    }
  }
  const Status reevaluated = reevaluate_enforcement("the grant is no longer enforceable locally");
  if (!reevaluated) {
    ICF_LOG_WARN("agent", "enforcement re-evaluation failed");
  }
  if (store_.needs_compaction()) {
    store::StoreMeta meta = recovery_.meta;
    meta.term = term_;
    meta.incarnation = incarnation_;
    meta.state_digest = registry_.digest();
    const Status compacted = store_.compact(registry_, meta, clock_->now());
    if (!compacted) {
      ICF_LOG_WARN("agent", "compaction failed");
    }
  }
  (void)loop_.schedule(clock_->now().plus(kTickInterval), [this]() { tick(); });
}

}  // namespace icf::runtime

