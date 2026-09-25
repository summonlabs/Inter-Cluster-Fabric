#include "icf/runtime/coordinator.hpp"

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

template <class Message>
Status send_to(net::Connection* connection, wire::MessageType type, const Message& message) {
  if (connection == nullptr) {
    return Status::ok();
  }
  Result<std::vector<std::byte>> payload = wire::encode_message(message);
  if (!payload) {
    return payload.status();
  }
  return connection->queue_frame(type, payload.value(), connection->signing_enabled());
}

constexpr std::uint64_t kVirtualConnection = 0;
constexpr Duration kTickInterval = Duration::from_millis(500);

}  // namespace

Coordinator::Coordinator(Config config, const Clock& clock)
    : config_(std::move(config)), clock_(&clock), loop_(clock), rng_(entropy_seed()) {}

Coordinator::~Coordinator() = default;

Result<std::unique_ptr<Coordinator>> Coordinator::create(Config config, const Clock& clock) {
  if (config.domain.empty()) {
    return invalid("the coordinator requires an authority domain identity");
  }
  if (config.state_directory.empty()) {
    return invalid("the coordinator requires a state directory");
  }
  auto coordinator = std::unique_ptr<Coordinator>(new Coordinator(std::move(config), clock));
  const Status started = coordinator->start();
  if (!started) {
    return started;
  }
  return coordinator;
}

Status Coordinator::load_state() {
  store::DurableStore::Options options;
  options.directory = config_.state_directory;
  options.snapshot_name = "coordinator.snapshot";
  options.wal_name = "coordinator.wal";
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

Status Coordinator::begin_incarnation() {
  previous_incarnation_ = recovery_.meta.incarnation;
  const Result<Term> next_term = recovery_.meta.term.next();
  term_ = next_term ? next_term.value() : Term(UINT64_MAX);
  incarnation_ = IncarnationId::random(rng_);
  started_at_ = clock_->now();

  // The new term is durable before anything else happens, so a restart can never leave an old
  // term in force while the runtime already answers requests under the new one.
  const Result<Sequence> meta = store_.append_meta(
      store::StoreMeta{term_, incarnation_, recovery_.meta.revision, store_.last_sequence(), started_at_,
                       recovery_.meta.truncations, registry_.digest()},
      started_at_);
  if (!meta) {
    return meta.status();
  }

  if (recovery_.recovered_from_store) {
    // Everything dynamic that survived the restart is historical. Fence it before serving.
    Result<FenceOutcome> fenced =
        fence_recovered_state(registry_, started_at_, "coordinator-recovery", previous_incarnation_, term_);
    if (!fenced) {
      return fenced.status();
    }
    const Result<Sequence> incident = store_.append_incident(
        std::string("recovered from store: ") + std::to_string(fenced.value().grants_fenced) +
            " grants fenced, " + std::to_string(fenced.value().reservations_released) + " reservations released",
        started_at_);
    if (!incident) {
      return incident.status();
    }
    // Persist the fenced state so a second recovery observes the same picture.
    for (const auto& entry : registry_.grants()) {
      store::Mutation mutation;
      mutation.kind = store::MutationKind::GrantPut;
      mutation.grant = entry.second;
      const Status appended = append_mutation(mutation);
      if (!appended) {
        return appended;
      }
    }
    for (const auto& entry : registry_.reservations()) {
      store::Mutation mutation;
      mutation.kind = store::MutationKind::ReservationPut;
      mutation.reservation = entry.second;
      const Status appended = append_mutation(mutation);
      if (!appended) {
        return appended;
      }
    }
    for (const auto& entry : registry_.clusters()) {
      store::Mutation mutation;
      mutation.kind = store::MutationKind::ClusterPut;
      mutation.cluster = entry.second;
      const Status appended = append_mutation(mutation);
      if (!appended) {
        return appended;
      }
    }
  }
  return append_audit("coordinator", "begin-incarnation", incarnation_.to_string(), Outcome::Ok,
                      std::string("term=") + std::to_string(term_.value()) +
                          (recovery_.recovered_from_store ? " recovered=true" : " recovered=false"));
}

Status Coordinator::start() {
  if (started_) {
    return Status::make(Outcome::AlreadyExists, "the coordinator is already started");
  }
  const Status loaded = load_state();
  if (!loaded) {
    return loaded;
  }
  const Status begun = begin_incarnation();
  if (!begun) {
    return begun;
  }
  const Status listening = listen();
  if (!listening) {
    return listening;
  }
  const Status timers = install_timers();
  if (!timers) {
    return timers;
  }
  started_ = true;
  ICF_LOG_INFO_KF("coordinator", "authority term established",
                  (std::initializer_list<std::pair<std::string_view, std::string_view>>{
                      {"term", std::to_string(term_.value()).c_str()},
                      {"domain", config_.domain.c_str()}}));
  return compact_if_needed();
}

Status Coordinator::listen() {
  std::uint16_t bound = 0;
  Result<net::TcpListener> listener =
      net::TcpListener::bind(config_.listen_address, config_.listen_port, 64, bound);
  if (!listener) {
    return listener.status();
  }
  listener_ = std::move(listener.value());
  port_ = bound;
  loop_.set_max_connections(config_.max_connections);

  net::EventLoop::ListenerHandler handler = [this](net::Socket socket) -> Status {
    net::Connection::Config connection_config;
    connection_config.idle_deadline = config_.agent_idle_deadline;
    // The handshake arrives unsigned: the coordinator cannot know which key to verify with until
    // it has read the authority domain the peer claims. Signing is enabled from the answer on.
    connection_config.verify_key.clear();
    connection_config.sign_outbound = false;
    Result<std::uint64_t> adopted =
        loop_.adopt(std::move(socket), std::move(connection_config),
                    [this](net::Connection& connection, const wire::Frame& frame) {
                      return handle_message(connection.id(), frame);
                    },
                    [this](net::Connection& connection, const Status& reason) {
                      handle_disconnect(connection.id(), reason);
                    });
    if (!adopted) {
      return adopted.status();
    }
    return Status::ok();
  };
  const Status added = loop_.add_listener(std::move(listener_), std::move(handler));
  if (!added) {
    return added;
  }
  if (!config_.readiness_file.empty()) {
    std::ofstream ready(config_.readiness_file, std::ios::binary | std::ios::trunc);
    if (ready) {
      ready << "address=" << config_.listen_address << "\n";
      ready << "port=" << port_ << "\n";
      ready << "domain=" << config_.domain.str() << "\n";
      ready << "term=" << term_.value() << "\n";
      ready << "incarnation=" << incarnation_.to_string() << "\n";
      ready << "view_digest=" << registry_.digest().hex() << "\n";
      ready.flush();
    }
  }
  return Status::ok();
}

Status Coordinator::install_timers() {
  const Timestamp now = clock_->now();
  (void)loop_.schedule(now, [this]() { tick(); });
  return Status::ok();
}

Status Coordinator::serve() { return loop_.run(); }

void Coordinator::stop() noexcept { loop_.stop(); }

Status Coordinator::append_mutation(const store::Mutation& mutation) {
  const Timestamp now = clock_->now();
  const Result<Sequence> appended = store_.append(mutation, now);
  if (!appended) {
    return appended.status();
  }
  return Status::ok();
}

Status Coordinator::append_audit(std::string actor, std::string action, std::string subject, Outcome outcome,
                                 std::string detail) {
  const Timestamp now = clock_->now();
  if (registry_.audit().size() >= limits::kMaxAuditRecords) {
    return Status::ok();  // the bounded trail stops growing; the state change itself already happened
  }
  const Status recorded = runtime::append_audit(registry_, now, std::move(actor), std::move(action),
                                                std::move(subject), outcome, std::move(detail));
  if (!recorded) {
    return recorded;
  }
  store::Mutation mutation;
  mutation.kind = store::MutationKind::AuditAppend;
  mutation.audit = registry_.audit().back();
  return append_mutation(mutation);
}

Status Coordinator::compact_if_needed() {
  if (!store_.needs_compaction()) {
    return Status::ok();
  }
  store::StoreMeta meta = recovery_.meta;
  meta.term = term_;
  meta.incarnation = incarnation_;
  meta.revision = Revision(registry_.counts().clusters + registry_.counts().contracts + registry_.counts().grants);
  meta.truncations = recovery_.meta.truncations;
  meta.state_digest = registry_.digest();
  return store_.compact(registry_, meta, clock_->now());
}

net::Connection* Coordinator::connection_for(std::uint64_t id) {
  if (id == kVirtualConnection) {
    return nullptr;
  }
  return loop_.find(id);
}

std::vector<std::byte> Coordinator::channel_key_for(const AuthorityDomainId& domain) const {
  const auto it = config_.domain_keys.find(domain.str());
  if (it == config_.domain_keys.end() || it->second.empty()) {
    return {};
  }
  return std::vector<std::byte>(reinterpret_cast<const std::byte*>(it->second.data()),
                                reinterpret_cast<const std::byte*>(it->second.data()) + it->second.size());
}

PeerSession* Coordinator::session_for(std::uint64_t connection_id) {
  const auto it = sessions_.find(connection_id);
  return it == sessions_.end() ? nullptr : &it->second;
}

const PeerSession* Coordinator::session_for(std::uint64_t connection_id) const {
  const auto it = sessions_.find(connection_id);
  return it == sessions_.end() ? nullptr : &it->second;
}

Status Coordinator::require_session(std::uint64_t connection_id, const SessionToken& token, PeerSession*& session) {
  session = session_for(connection_id);
  if (session == nullptr || !session->hello_complete) {
    ++rejected_replays_;
    return Status::make(Outcome::Unauthorized, "message received before a completed handshake");
  }
  if (session->token != token) {
    ++rejected_replays_;
    return Status::make(Outcome::Replayed, "session token does not match the established session");
  }
  return Status::ok();
}

Status Coordinator::send_refuse(std::uint64_t connection_id, Outcome outcome, const std::string& detail) {
  wire::RefuseMessage message;
  message.outcome = outcome;
  message.detail = detail;
  ++refusals_;
  return send_to(connection_for(connection_id), wire::MessageType::Refuse, message);
}

Status Coordinator::send_error(std::uint64_t connection_id, const Uuid& request, Outcome outcome,
                               const std::string& detail) {
  wire::ErrorMessage message;
  message.request = request;
  message.outcome = outcome;
  message.detail = detail;
  return send_to(connection_for(connection_id), wire::MessageType::Error, message);
}

Status Coordinator::handle_message(std::uint64_t connection_id, const wire::Frame& frame) {
  switch (frame.header.type) {
    case wire::MessageType::Hello:
      return on_hello(connection_id, frame);
    case wire::MessageType::ReportCluster:
      return on_report_cluster(connection_id, frame);
    case wire::MessageType::ContractConsent:
      return on_contract_consent(connection_id, frame);
    case wire::MessageType::GrantPrepared:
      return on_grant_prepared(connection_id, frame);
    case wire::MessageType::GrantCommitted:
      return on_grant_committed(connection_id, frame);
    case wire::MessageType::GrantAborted:
      return on_grant_aborted(connection_id, frame);
    case wire::MessageType::FenceAck:
      return on_fence_ack(connection_id, frame);
    case wire::MessageType::Withdraw:
      return on_withdraw(connection_id, frame);
    case wire::MessageType::StatusReport:
      return on_status_report(connection_id, frame);
    case wire::MessageType::Query:
      return on_query(connection_id, frame);
    case wire::MessageType::Admin:
      return on_admin(connection_id, frame);
    case wire::MessageType::Ping:
      return on_ping(connection_id, frame);
    case wire::MessageType::Pong:
      // A keep-alive reply: it confirms the peer is alive and needs no answer. Answering it would
      // start an unbounded exchange of replies.
      ++pongs_received_;
      return Status::ok();
    case wire::MessageType::Error:
      // A peer reports a problem it already observed. Replying with another error would make two
      // peers trade errors forever, so a received error is recorded and dropped.
      ++errors_received_;
      return Status::ok();
    default:
      ++rejected_frames_;
      return send_error(connection_id, Uuid{}, Outcome::Unsupported,
                        std::string("message type is not accepted by the coordinator: ") +
                            wire::to_string(frame.header.type));
  }
}

void Coordinator::handle_disconnect(std::uint64_t connection_id, const Status& reason) {
  // Input that the framing layer refused never reaches a message handler, so the refusal is
  // counted here; otherwise a peer that only ever sends garbage would look like a quiet session.
  switch (reason.outcome()) {
    case Outcome::Invalid:
    case Outcome::Corrupt:
    case Outcome::Unauthorized:
    case Outcome::Incompatible:
    case Outcome::Replayed:
      ++rejected_frames_;
      break;
    default:
      break;
  }
  const auto it = sessions_.find(connection_id);
  if (it == sessions_.end()) {
    return;
  }
  const ClusterId cluster = it->second.cluster;
  sessions_.erase(it);
  if (cluster.empty()) {
    return;
  }
  // Any grant flow that was waiting on this peer becomes indeterminate: it is not usable until a
  // fresh status exchange resolves it.
  for (auto& entry : pending_) {
    PendingGrant& pending = entry.second;
    for (std::size_t side = 0; side < model::kPartyCount; ++side) {
      if (pending.targets[side].connection_id == connection_id) {
        pending.targets[side].connected = false;
        pending.targets[side].connection_id = 0;
      }
    }
    (void)pending;
  }
  for (auto& entry : registry_.grants()) {
    model::GrantRecord& grant = entry.second;
    if (grant.state != model::GrantState::Preparing && grant.state != model::GrantState::Prepared) {
      continue;
    }
    const model::ContractRecord* contract = registry_.find_contract(grant.contract);
    if (contract == nullptr) {
      continue;
    }
    bool touches = false;
    for (const model::PartyRef& party : contract->parties) {
      if (party.cluster == cluster) {
        touches = true;
      }
    }
    if (!touches) {
      continue;
    }
    grant.state = model::GrantState::Indeterminate;
    grant.note = "the cluster agent disconnected before the commit acknowledgement";
    store::Mutation mutation;
    mutation.kind = store::MutationKind::GrantPut;
    mutation.grant = grant;
    const Status persisted = append_mutation(mutation);
    if (!persisted) {
      ICF_LOG_ERROR("coordinator", "failed to persist an indeterminate grant");
    }
  }
}

Status Coordinator::on_hello(std::uint64_t connection_id, const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::HelloMessage> hello = wire::decode_hello(reader);
  if (!hello) {
    ++rejected_frames_;
    return send_error(connection_id, Uuid{}, hello.status().outcome(), hello.status().message());
  }
  const Status end = reader.expect_end();
  if (!end) {
    ++rejected_frames_;
    return send_error(connection_id, Uuid{}, Outcome::Invalid, end.message());
  }
  const wire::HelloMessage& request = hello.value();

  wire::HelloAckMessage ack;
  ack.coordinator = incarnation_;
  ack.coordinator_term = term_;
  ack.view_digest = registry_.digest();
  const std::uint16_t negotiated = std::min(request.protocol_max, limits::kProtocolVersionMax);
  const std::uint16_t required = std::max(request.protocol_min, limits::kProtocolVersionMin);
  if (negotiated < required) {
    ack.outcome = Outcome::Unsupported;
    ack.detail = "no protocol version is supported by both peers";
    ++refusals_;
    return send_to(connection_for(connection_id), wire::MessageType::HelloAck, ack);
  }
  ack.negotiated_version = negotiated;

  net::Connection* connection = connection_for(connection_id);
  const std::vector<std::byte> key = channel_key_for(request.domain);
  if (!key.empty() && connection != nullptr) {
    connection->enable_signing(key);
  }

  if (request.role == wire::PeerRole::Observer) {
    PeerSession session;
    session.role = wire::PeerRole::Observer;
    session.domain = request.domain;
    session.token = SessionToken::random(rng_);
    session.hello_complete = true;
    session.connected_at = clock_->now();
    session.connection_id = connection_id;
    session.signing = !key.empty();
    ack.session = session.token;
    ack.outcome = Outcome::Ok;
    ack.detail = "observer session established";
    sessions_[connection_id] = session;
    return send_to(connection, wire::MessageType::HelloAck, ack);
  }

  if (request.cluster.empty()) {
    ack.outcome = Outcome::Invalid;
    ack.detail = "an agent handshake must name a cluster identity";
    ++refusals_;
    return send_to(connection, wire::MessageType::HelloAck, ack);
  }
  if (request.domain.empty()) {
    ack.outcome = Outcome::Invalid;
    ack.detail = "an agent handshake must name an authority domain";
    ++refusals_;
    return send_to(connection, wire::MessageType::HelloAck, ack);
  }
  if ((request.capabilities & wire::kCapabilityTwoSidedConsent) == 0) {
    ack.outcome = Outcome::Unsupported;
    ack.detail = "the agent does not declare two-sided consent support";
    ++refusals_;
    return send_to(connection, wire::MessageType::HelloAck, ack);
  }

  model::ClusterRecord* cluster = registry_.find_cluster(request.cluster);
  std::vector<GrantId> fenced_grants;
  if (cluster == nullptr) {
    if (!config_.allow_agent_registration) {
      ack.outcome = Outcome::NotFound;
      ack.detail = "cluster identity is not registered and agent-driven registration is disabled";
      ++refusals_;
      return send_to(connection, wire::MessageType::HelloAck, ack);
    }
    model::ClusterRecord record;
    record.id = request.cluster;
    record.domain = request.domain;
    record.incarnation = request.incarnation;
    record.generation = request.generation;
    record.policy_generation = request.policy_generation;
    record.state = model::ClusterState::Unknown;
    record.last_seen = clock_->now();
    record.content_digest = request.content_digest;
    record.provenance.source = model::EvidenceSource::AgentReported;
    record.provenance.verification = model::VerificationState::Verified;
    record.provenance.observed_at = clock_->now();
    record.provenance.evidence_digest = request.content_digest;
    const Status stored = registry_.put_cluster(record);
    if (!stored) {
      ack.outcome = stored.outcome();
      ack.detail = stored.message();
      ++refusals_;
      return send_to(connection, wire::MessageType::HelloAck, ack);
    }
    cluster = registry_.find_cluster(request.cluster);
    store::Mutation mutation;
    mutation.kind = store::MutationKind::ClusterPut;
    mutation.cluster = *cluster;
    const Status persisted = append_mutation(mutation);
    if (!persisted) {
      return persisted;
    }
    const Status audited = append_audit("coordinator", "register-cluster", request.cluster.str(), Outcome::Ok,
                                        "cluster identity registered from an agent handshake");
    if (!audited) {
      return audited;
    }
  } else {
    if (cluster->domain != request.domain) {
      ack.outcome = Outcome::Refused;
      ack.detail = "the cluster is governed by a different authority domain";
      ++refusals_;
      return send_to(connection, wire::MessageType::HelloAck, ack);
    }
    if (request.generation < cluster->generation) {
      ack.outcome = Outcome::Stale;
      ack.detail = "the agent presents a generation older than the authoritative one";
      ++refusals_;
      const Status audited = append_audit("coordinator", "reject-stale-handshake", request.cluster.str(),
                                          Outcome::Stale, "older generation presented");
      if (!audited) {
        return audited;
      }
      return send_to(connection, wire::MessageType::HelloAck, ack);
    }
    const bool reincarnated = request.incarnation != cluster->incarnation;
    if (reincarnated && request.generation == cluster->generation) {
      ack.outcome = Outcome::Stale;
      ack.detail = "a new incarnation must present a generation greater than the recorded one";
      ++refusals_;
      return send_to(connection, wire::MessageType::HelloAck, ack);
    }
    if (reincarnated) {
      const IncarnationId previous = cluster->incarnation;
      const Generation generation = request.generation;
      cluster->incarnation = request.incarnation;
      cluster->generation = generation;
      // The digest the agent presents belongs to the new incarnation; keeping the old digest
      // would make the very next report look like a same-generation content conflict.
      cluster->content_digest = request.content_digest;
      cluster->generation_conflict = false;
      cluster->conflicting_generation.reset();
      cluster->last_seen = clock_->now();
      ++cluster->incarnation_changes;
      cluster->provenance.source = model::EvidenceSource::AgentReported;
      cluster->provenance.verification = model::VerificationState::Verified;
      cluster->provenance.observed_at = clock_->now();
      const Status fenced = fence_cluster(request.cluster, model::FenceTrigger::ClusterReincarnation,
                                          request.incarnation, previous, generation);
      if (!fenced) {
        return fenced;
      }
      cluster = registry_.find_cluster(request.cluster);
      for (const auto& entry : registry_.grants()) {
        if (entry.second.state == model::GrantState::Fenced) {
          fenced_grants.push_back(entry.first);
        }
      }
      const Status persisted = [&]() {
        store::Mutation mutation;
        mutation.kind = store::MutationKind::ClusterPut;
        mutation.cluster = *cluster;
        return append_mutation(mutation);
      }();
      if (!persisted) {
        return persisted;
      }
      ack.detail = "cluster reincarnation recorded; dependent grants were fenced";
    } else if (request.policy_generation != cluster->policy_generation) {
      if (request.policy_generation < cluster->policy_generation) {
        ack.outcome = Outcome::Stale;
        ack.detail = "the agent presents a policy generation older than the authoritative one";
        ++refusals_;
        return send_to(connection, wire::MessageType::HelloAck, ack);
      }
      cluster->policy_generation = request.policy_generation;
      cluster->last_seen = clock_->now();
      const Status fenced = fence_cluster(request.cluster, model::FenceTrigger::PolicyGenerationChange,
                                          cluster->incarnation, cluster->incarnation, cluster->generation);
      if (!fenced) {
        return fenced;
      }
      const Status persisted = [&]() {
        store::Mutation mutation;
        mutation.kind = store::MutationKind::ClusterPut;
        mutation.cluster = *registry_.find_cluster(request.cluster);
        return append_mutation(mutation);
      }();
      if (!persisted) {
        return persisted;
      }
      ack.detail = "bind policy generation changed; dependent grants were fenced";
    } else {
      cluster->last_seen = clock_->now();
      ack.detail = "handshake accepted";
    }
  }

  PeerSession session;
  session.role = wire::PeerRole::Agent;
  session.cluster = request.cluster;
  session.domain = request.domain;
  session.incarnation = request.incarnation;
  session.generation = request.generation;
  session.policy_generation = request.policy_generation;
  session.agent_term = request.agent_term;
  session.token = SessionToken::random(rng_);
  session.hello_complete = true;
  session.connected_at = clock_->now();
  session.connection_id = connection_id;
  session.signing = !key.empty();

  const model::ClusterRecord* current = registry_.find_cluster(request.cluster);
  if (current != nullptr && current->generation_conflict) {
    session.hello_complete = true;
    ack.outcome = Outcome::Conflicting;
    ack.detail = "the cluster has an unresolved generation conflict; resolve it before reconnecting";
  } else {
    ack.outcome = Outcome::Ok;
  }
  ack.session = session.token;
  ack.view_digest = registry_.digest();
  ack.revalidate = fenced_grants;
  sessions_[connection_id] = session;

  ICF_LOG_INFO_KF("coordinator", "agent handshake",
                  (std::initializer_list<std::pair<std::string_view, std::string_view>>{
                      {"cluster", request.cluster.c_str()},
                      {"generation", std::to_string(request.generation.value()).c_str()},
                      {"outcome", ::icf::to_string(ack.outcome)}}));

  const Status sent = send_to(connection, wire::MessageType::HelloAck, ack);
  if (!sent) {
    return sent;
  }
  if (!fenced_grants.empty()) {
    wire::FenceMessage fence;
    fence.session = session.token;
    fence.coordinator_term = term_;
    fence.grants = fenced_grants;
    fence.reason = "cluster reincarnation or policy change fenced these grants";
    const Status fenced = send_to(connection, wire::MessageType::Fence, fence);
    if (!fenced) {
      return fenced;
    }
  }
  // Ask the peer for its durable enforcement state so that any interrupted commit/ack exchange is
  // resolved instead of being assumed either way.
  wire::StatusRequestMessage status_request;
  status_request.session = session.token;
  status_request.request = Uuid::random(rng_);
  return send_to(connection, wire::MessageType::StatusRequest, status_request);
}

Status Coordinator::on_report_cluster(std::uint64_t connection_id, const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::ReportClusterMessage> report = wire::decode_report_cluster(reader);
  if (!report) {
    ++rejected_frames_;
    return send_error(connection_id, Uuid{}, report.status().outcome(), report.status().message());
  }
  PeerSession* session = nullptr;
  const Status authorized = require_session(connection_id, report.value().session, session);
  if (!authorized) {
    return send_error(connection_id, Uuid{}, authorized.outcome(), authorized.message());
  }
  if (session->role != wire::PeerRole::Agent) {
    return send_error(connection_id, Uuid{}, Outcome::Unauthorized, "only an agent may report cluster state");
  }
  model::ClusterRecord incoming = report.value().cluster;
  if (incoming.id != session->cluster) {
    return send_error(connection_id, Uuid{}, Outcome::Unauthorized,
                      "the report names a cluster this session does not own");
  }
  model::ClusterRecord* cluster = registry_.find_cluster(session->cluster);
  if (cluster == nullptr) {
    return send_error(connection_id, Uuid{}, Outcome::NotFound, "the cluster is not registered");
  }
  wire::ReportAckMessage ack;
  ack.session = session->token;
  ack.view_digest = registry_.digest();
  ack.revision = cluster->revision;

  if (incoming.generation < cluster->generation) {
    ack.outcome = Outcome::Stale;
    ack.detail = "the report carries a superseded generation";
    ++refusals_;
    return send_to(connection_for(connection_id), wire::MessageType::ReportAck, ack);
  }
  if (incoming.incarnation != cluster->incarnation) {
    ack.outcome = Outcome::Stale;
    ack.detail = "the report was produced by an incarnation that is not the current one";
    ++refusals_;
    return send_to(connection_for(connection_id), wire::MessageType::ReportAck, ack);
  }
  const bool policy_advanced = incoming.policy_generation > cluster->policy_generation;
  if (!policy_advanced && incoming.generation == cluster->generation && !incoming.content_digest.is_zero() &&
      !cluster->content_digest.is_zero() && incoming.content_digest != cluster->content_digest) {
    // Two different contents claim the same generation: a deterministic conflict, never a silent
    // last-writer-wins.
    cluster->generation_conflict = true;
    cluster->conflicting_generation = incoming.generation;
    session->generation = incoming.generation;
    const Status fenced = fence_cluster(cluster->id, model::FenceTrigger::Manual, cluster->incarnation,
                                        cluster->incarnation, cluster->generation);
    if (!fenced) {
      return fenced;
    }
    store::Mutation mutation;
    mutation.kind = store::MutationKind::ClusterPut;
    mutation.cluster = *cluster;
    const Status persisted = append_mutation(mutation);
    if (!persisted) {
      return persisted;
    }
    const Status audited = append_audit("coordinator", "generation-conflict", cluster->id.str(), Outcome::Conflicting,
                                        "two reports claim the same generation with different contents");
    if (!audited) {
      return audited;
    }
    ack.outcome = Outcome::Conflicting;
    ack.detail = "a different content already claims this generation; an operator must resolve the conflict";
    ack.view_digest = registry_.digest();
    return send_to(connection_for(connection_id), wire::MessageType::ReportAck, ack);
  }

  const bool policy_changed = incoming.policy_generation != cluster->policy_generation;
  if (incoming.policy_generation < cluster->policy_generation) {
    ack.outcome = Outcome::Stale;
    ack.detail = "the report carries a superseded policy generation";
    ++refusals_;
    return send_to(connection_for(connection_id), wire::MessageType::ReportAck, ack);
  }

  incoming.domain = cluster->domain;
  incoming.revision = cluster->revision.next().has_value() ? cluster->revision.next().value() : cluster->revision;
  incoming.provenance.source = model::EvidenceSource::AgentReported;
  incoming.provenance.verification = model::VerificationState::Verified;
  incoming.provenance.observed_at = clock_->now();
  incoming.provenance.evidence_digest = incoming.content_digest;
  incoming.provenance.session = session->token;
  incoming.incarnation_changes = cluster->incarnation_changes;
  incoming.generation_conflict = false;
  const Status stored = registry_.put_cluster(incoming);
  if (!stored) {
    return send_error(connection_id, Uuid{}, stored.outcome(), stored.message());
  }
  cluster = registry_.find_cluster(session->cluster);
  session->generation = incoming.generation;
  session->policy_generation = incoming.policy_generation;
  store::Mutation mutation;
  mutation.kind = store::MutationKind::ClusterPut;
  mutation.cluster = *cluster;
  const Status persisted = append_mutation(mutation);
  if (!persisted) {
    return persisted;
  }
  if (policy_changed) {
    const Status fenced = fence_cluster(cluster->id, model::FenceTrigger::PolicyGenerationChange, cluster->incarnation,
                                        cluster->incarnation, cluster->generation);
    if (!fenced) {
      return fenced;
    }
  }
  registry_.recompute_path_states();
  ack.outcome = Outcome::Ok;
  ack.detail = "cluster state accepted";
  ack.revision = cluster->revision;
  ack.view_digest = registry_.digest();
  const Status audited = append_audit("agent", "report-cluster", cluster->id.str(), Outcome::Ok,
                                      std::string("generation=") + std::to_string(cluster->generation.value()));
  if (!audited) {
    return audited;
  }
  return send_to(connection_for(connection_id), wire::MessageType::ReportAck, ack);
}

Status Coordinator::on_contract_consent(std::uint64_t connection_id, const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::ContractConsentMessage> consent = wire::decode_contract_consent(reader);
  if (!consent) {
    ++rejected_frames_;
    return send_error(connection_id, Uuid{}, consent.status().outcome(), consent.status().message());
  }
  PeerSession* session = nullptr;
  const Status authorized = require_session(connection_id, consent.value().session, session);
  if (!authorized) {
    return send_error(connection_id, Uuid{}, authorized.outcome(), authorized.message());
  }
  if (session->role != wire::PeerRole::Agent) {
    return send_error(connection_id, Uuid{}, Outcome::Unauthorized, "only an agent may consent to a contract");
  }
  model::ContractRecord* contract = registry_.find_contract(consent.value().contract);
  if (contract == nullptr) {
    return send_error(connection_id, Uuid{}, Outcome::NotFound, "the contract is not registered");
  }
  const int side = contract->side_of(session->cluster);
  if (side < 0) {
    return send_error(connection_id, Uuid{}, Outcome::Unauthorized, "the contract does not name this cluster");
  }
  if (consent.value().terms_digest != contract->terms_digest) {
    const Status audited = append_audit("agent", "consent-mismatch", contract->id.to_string(), Outcome::Conflicting,
                                        "the consent covers different terms than the contract");
    if (!audited) {
      return audited;
    }
    return send_error(connection_id, Uuid{}, Outcome::Conflicting,
                      "the consent does not cover the terms held for this contract");
  }
  const model::PartyRef& party = contract->parties[static_cast<std::size_t>(side)];
  if (consent.value().endpoint != party.endpoint) {
    return send_error(connection_id, Uuid{}, Outcome::Invalid, "the consent names an endpoint this party does not own");
  }
  if (consent.value().incarnation != session->incarnation || consent.value().generation != session->generation) {
    ++rejected_replays_;
    return send_error(connection_id, Uuid{}, Outcome::Stale,
                      "the consent was produced by a superseded incarnation or generation");
  }

  model::ConsentRecord record;
  record.cluster = session->cluster;
  record.endpoint = consent.value().endpoint;
  record.incarnation = consent.value().incarnation;
  record.generation = consent.value().generation;
  record.policy_generation = consent.value().policy_generation;
  record.agent_term = consent.value().agent_term;
  record.terms_digest = consent.value().terms_digest;
  record.decision = consent.value().decision;
  record.decided_at = clock_->now();
  record.session = session->token;
  record.authenticity = session->signing ? model::TransportAuthenticity::SharedKeyMac
                                         : model::TransportAuthenticity::None;
  record.reason = consent.value().reason;

  const auto existing = contract->consents[static_cast<std::size_t>(side)];
  if (existing.has_value() && existing->decision == record.decision &&
      existing->terms_digest == record.terms_digest && existing->generation == record.generation) {
    // Idempotent replay of the same consent under the live session: accepted without change and
    // without a second write, so a retransmitted consent cannot move the state at all.
    return Status::ok();
  }
  contract->consents[static_cast<std::size_t>(side)] = record;
  contract->updated_at = clock_->now();
  if (contract->revision.increment()) {
    // revision advances
  }
  if (record.decision == model::ConsentDecision::Refused) {
    contract->state = model::ContractState::Refused;
  } else if (contract->both_consented()) {
    contract->state = model::ContractState::Consented;
  } else {
    contract->state = model::ContractState::AwaitingConsent;
  }
  store::Mutation mutation;
  mutation.kind = store::MutationKind::ContractPut;
  mutation.contract = *contract;
  const Status persisted = append_mutation(mutation);
  if (!persisted) {
    return persisted;
  }
  const Status audited = append_audit("agent", "contract-consent", contract->id.to_string(), Outcome::Ok,
                                      std::string("decision=") + to_string(record.decision));
  if (!audited) {
    return audited;
  }
  return Status::ok();
}

Status Coordinator::on_ping(std::uint64_t connection_id, const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::PingMessage> ping = wire::decode_ping(reader);
  if (!ping) {
    ++rejected_frames_;
    return send_error(connection_id, Uuid{}, ping.status().outcome(), ping.status().message());
  }
  wire::PongMessage pong;
  pong.sequence = ping.value().sequence;
  return send_to(connection_for(connection_id), wire::MessageType::Pong, pong);
}

Coordinator::SendTarget Coordinator::target_for(const ClusterId& cluster) const {
  SendTarget target;
  const PeerSession* best = nullptr;
  for (const auto& entry : sessions_) {
    const PeerSession& session = entry.second;
    if (session.role != wire::PeerRole::Agent || !session.hello_complete || session.cluster != cluster) {
      continue;
    }
    if (best == nullptr || best->connected_at < session.connected_at ||
        (best->connected_at == session.connected_at && best->connection_id < session.connection_id)) {
      best = &session;
    }
  }
  if (best == nullptr) {
    return target;
  }
  target.connected = true;
  target.connection_id = best->connection_id;
  target.token = best->token;
  return target;
}

Status Coordinator::fence_plan_apply(const model::FencePlan& plan, const std::string& actor) {
  if (plan.actions.empty()) {
    return Status::ok();
  }
  const std::size_t audit_before = registry_.audit().size();
  Result<FenceOutcome> outcome = apply_fence_plan(registry_, plan, clock_->now(), actor);
  if (!outcome) {
    return outcome.status();
  }
  fences_ += outcome.value().grants_fenced;
  std::vector<GrantId> fenced_grants;
  for (const model::FenceAction& action : plan.actions) {
    switch (action.target) {
      case model::FenceTarget::Grant: {
        const model::GrantRecord* grant = registry_.find_grant(action.grant);
        if (grant == nullptr) {
          break;
        }
        store::Mutation mutation;
        mutation.kind = store::MutationKind::GrantPut;
        mutation.grant = *grant;
        const Status persisted = append_mutation(mutation);
        if (!persisted) {
          return persisted;
        }
        if (grant->state == model::GrantState::Fenced) {
          fenced_grants.push_back(grant->id);
        }
        break;
      }
      case model::FenceTarget::Contract: {
        const model::ContractRecord* contract = registry_.find_contract(action.contract);
        if (contract == nullptr) {
          break;
        }
        store::Mutation mutation;
        mutation.kind = store::MutationKind::ContractPut;
        mutation.contract = *contract;
        const Status persisted = append_mutation(mutation);
        if (!persisted) {
          return persisted;
        }
        break;
      }
      case model::FenceTarget::Reservation: {
        const model::ReservationRecord* reservation = registry_.find_reservation(action.reservation);
        if (reservation == nullptr) {
          break;
        }
        store::Mutation mutation;
        mutation.kind = store::MutationKind::ReservationPut;
        mutation.reservation = *reservation;
        const Status persisted = append_mutation(mutation);
        if (!persisted) {
          return persisted;
        }
        break;
      }
    }
  }
  for (const auto& entry : registry_.clusters()) {
    store::Mutation mutation;
    mutation.kind = store::MutationKind::ClusterPut;
    mutation.cluster = entry.second;
    const Status persisted = append_mutation(mutation);
    if (!persisted) {
      return persisted;
    }
  }
  for (std::size_t index = audit_before; index < registry_.audit().size(); ++index) {
    store::Mutation mutation;
    mutation.kind = store::MutationKind::AuditAppend;
    mutation.audit = registry_.audit()[index];
    const Status persisted = append_mutation(mutation);
    if (!persisted) {
      return persisted;
    }
  }
  // Tell every connected agent that participated in the fenced grants. A send failure is not
  // fatal: the reconnect status exchange resolves enforcement state anyway.
  if (!fenced_grants.empty()) {
    for (const auto& entry : sessions_) {
      const PeerSession& session = entry.second;
      if (session.role != wire::PeerRole::Agent || !session.hello_complete) {
        continue;
      }
      wire::FenceMessage fence;
      fence.session = session.token;
      fence.coordinator_term = term_;
      fence.grants = fenced_grants;
      fence.reason = std::string("fenced by ") + to_string(plan.trigger);
      (void)send_to(connection_for(entry.first), wire::MessageType::Fence, fence);
    }
  }
  return Status::ok();
}

Status Coordinator::fence_cluster(const ClusterId& cluster, model::FenceTrigger trigger,
                                  const IncarnationId& new_incarnation,
                                  const IncarnationId& previous_incarnation, const Generation& generation) {
  const model::FencePlan plan =
      plan_fence(registry_, trigger, cluster, new_incarnation, previous_incarnation, generation, term_);
  const Status applied = fence_plan_apply(plan, "coordinator");
  if (!applied) {
    return applied;
  }
  return append_audit("coordinator", "fence-cluster", cluster.str(), Outcome::Fenced,
                      std::string("trigger=") + to_string(trigger) +
                          " grants=" + std::to_string(plan.actions.size()));
}

Status Coordinator::reserve_capacity(const model::GrantRecord& grant, Timestamp at) {
  const model::ContractRecord* contract = registry_.find_contract(grant.contract);
  if (contract == nullptr) {
    return not_found("the grant references an unknown contract");
  }
  for (std::size_t side = 0; side < model::kPartyCount; ++side) {
    const model::PartyRef& party = contract->parties[side];
    model::ClusterRecord* cluster = registry_.find_cluster(party.cluster);
    if (cluster == nullptr) {
      return not_found("a bound cluster is not registered");
    }
    model::EndpointRecord* endpoint = nullptr;
    for (model::EndpointRecord& candidate : cluster->endpoints) {
      if (candidate.id == party.endpoint) {
        endpoint = &candidate;
        break;
      }
    }
    if (endpoint == nullptr) {
      return not_found("a bound endpoint scope is not registered");
    }
    const std::uint64_t requested = grant.capacity.value();
    const std::uint64_t already = endpoint->reserved.value();
    if (requested > endpoint->capacity.value() || already > endpoint->capacity.value() - requested) {
      return Status::make(Outcome::CapacityExceeded,
                          std::string("endpoint scope ") + endpoint->id.str() + " cannot reserve the requested capacity");
    }
    endpoint->reserved = CapacityUnits(already + requested);
    model::ReservationRecord reservation;
    reservation.id = ReservationId::random(rng_);
    reservation.grant = grant.id;
    reservation.endpoint = endpoint->id;
    reservation.cluster = cluster->id;
    reservation.amount = grant.capacity;
    reservation.created_at = at;
    reservation.provenance.source = model::EvidenceSource::DerivedFromTopology;
    reservation.provenance.verification = model::VerificationState::Verified;
    reservation.provenance.observed_at = at;
    const Status stored = registry_.put_reservation(reservation);
    if (!stored) {
      return stored;
    }
    store::Mutation reservation_mutation;
    reservation_mutation.kind = store::MutationKind::ReservationPut;
    reservation_mutation.reservation = reservation;
    const Status persisted_reservation = append_mutation(reservation_mutation);
    if (!persisted_reservation) {
      return persisted_reservation;
    }
    store::Mutation cluster_mutation;
    cluster_mutation.kind = store::MutationKind::ClusterPut;
    cluster_mutation.cluster = *cluster;
    const Status persisted_cluster = append_mutation(cluster_mutation);
    if (!persisted_cluster) {
      return persisted_cluster;
    }
  }
  return Status::ok();
}

Status Coordinator::finalise_grant(const GrantId& grant_id, Timestamp at) {
  model::GrantRecord* grant = registry_.find_grant(grant_id);
  if (grant == nullptr) {
    return not_found("the grant is not registered");
  }
  if (grant->state == model::GrantState::Committed || grant->state == model::GrantState::Active) {
    return Status::ok();
  }
  if (!grant->both_acknowledged()) {
    return Status::make(Outcome::Incomplete, "both parties have not acknowledged the grant");
  }
  const Status reserved = reserve_capacity(*grant, at);
  if (!reserved) {
    const Status aborted = abort_grant(grant_id, reserved.message());
    if (!aborted) {
      return aborted;
    }
    return reserved;
  }
  grant = registry_.find_grant(grant_id);
  grant->state = model::GrantState::Committed;
  grant->note = "committed by both cluster agents";
  grant->provenance.source = model::EvidenceSource::DerivedFromTopology;
  grant->provenance.verification = model::VerificationState::Verified;
  grant->provenance.observed_at = at;
  store::Mutation mutation;
  mutation.kind = store::MutationKind::GrantPut;
  mutation.grant = *grant;
  const Status persisted = append_mutation(mutation);
  if (!persisted) {
    return persisted;
  }
  ++commits_;
  pending_.erase(grant_id);
  return append_audit("coordinator", "commit-grant", grant_id.to_string(), Outcome::Ok,
                      "both cluster agents acknowledged the same attempt");
}

Status Coordinator::abort_grant(const GrantId& grant_id, const std::string& reason) {
  model::GrantRecord* grant = registry_.find_grant(grant_id);
  if (grant == nullptr) {
    pending_.erase(grant_id);
    return Status::ok();
  }
  if (grant->state == model::GrantState::Fenced || grant->state == model::GrantState::Withdrawn) {
    pending_.erase(grant_id);
    return Status::ok();
  }
  grant->state = model::GrantState::Aborted;
  grant->note = reason;
  store::Mutation mutation;
  mutation.kind = store::MutationKind::GrantPut;
  mutation.grant = *grant;
  const Status persisted = append_mutation(mutation);
  pending_.erase(grant_id);
  if (!persisted) {
    return persisted;
  }
  return append_audit("coordinator", "abort-grant", grant_id.to_string(), Outcome::Cancelled, reason);
}

Status Coordinator::prepare_grant(model::GrantRecord& grant) {
  const model::ContractRecord* contract = registry_.find_contract(grant.contract);
  if (contract == nullptr) {
    return not_found("the grant references an unknown contract");
  }
  if (contract->state != model::ContractState::Consented && contract->state != model::ContractState::Active) {
    return Status::make(Outcome::Incomplete, "both authority domains must consent before a grant can be prepared");
  }
  PendingGrant pending;
  pending.grant = grant.id;
  pending.contract = grant.contract;
  pending.deadline = clock_->now().plus(config_.grant_flow_deadline);
  for (std::size_t side = 0; side < model::kPartyCount; ++side) {
    pending.targets[side] = target_for(contract->parties[side].cluster);
    if (!pending.targets[side].connected) {
      return Status::make(Outcome::Unreachable,
                          std::string("cluster agent for ") + contract->parties[side].cluster.str() +
                              " is not connected");
    }
  }
  grant.state = model::GrantState::Preparing;
  grant.provenance.source = model::EvidenceSource::DerivedFromTopology;
  grant.provenance.verification = model::VerificationState::Verified;
  grant.provenance.observed_at = clock_->now();
  store::Mutation mutation;
  mutation.kind = store::MutationKind::GrantPut;
  mutation.grant = grant;
  const Status persisted = append_mutation(mutation);
  if (!persisted) {
    return persisted;
  }
  registry_.put_grant(grant);
  pending_[grant.id] = pending;

  const model::GrantRecord* stored = registry_.find_grant(grant.id);
  if (stored == nullptr) {
    return internal_error("the grant disappeared after being stored");
  }
  for (std::size_t side = 0; side < model::kPartyCount; ++side) {
    wire::PrepareGrantMessage message;
    message.session = pending.targets[side].token;
    message.grant = *stored;
    const Status sent = send_to(connection_for(pending.targets[side].connection_id), wire::MessageType::PrepareGrant,
                                message);
    if (!sent) {
      return sent;
    }
  }
  return Status::ok();
}

Status Coordinator::commit_grant(const GrantId& grant_id) {
  model::GrantRecord* grant = registry_.find_grant(grant_id);
  if (grant == nullptr) {
    return not_found("the grant is not registered");
  }
  const auto pending_it = pending_.find(grant_id);
  if (pending_it == pending_.end()) {
    return Status::make(Outcome::Indeterminate, "the grant flow is no longer pending");
  }
  PendingGrant& pending = pending_it->second;
  for (std::size_t side = 0; side < model::kPartyCount; ++side) {
    if (!pending.targets[side].connected) {
      grant->state = model::GrantState::Indeterminate;
      grant->note = "a cluster agent disconnected before the commit was issued";
      store::Mutation mutation;
      mutation.kind = store::MutationKind::GrantPut;
      mutation.grant = *grant;
      const Status persisted = append_mutation(mutation);
      std::size_t narrowed = 0;
      (void)narrowed;
      return persisted;
    }
  }
  grant->state = model::GrantState::Prepared;
  grant->note = "both cluster agents prepared the same attempt";
  store::Mutation mutation;
  mutation.kind = store::MutationKind::GrantPut;
  mutation.grant = *grant;
  const Status persisted = append_mutation(mutation);
  if (!persisted) {
    return persisted;
  }
  for (std::size_t side = 0; side < model::kPartyCount; ++side) {
    wire::CommitGrantMessage message;
    message.session = pending.targets[side].token;
    message.grant = grant_id;
    message.attempt = grant->attempt;
    const Status sent = send_to(connection_for(pending.targets[side].connection_id), wire::MessageType::CommitGrant,
                                message);
    if (!sent) {
      return sent;
    }
  }
  return Status::ok();
}

Status Coordinator::on_grant_prepared(std::uint64_t connection_id, const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::GrantPreparedMessage> prepared = wire::decode_grant_prepared(reader);
  if (!prepared) {
    ++rejected_frames_;
    return send_error(connection_id, Uuid{}, prepared.status().outcome(), prepared.status().message());
  }
  PeerSession* session = nullptr;
  const Status authorized = require_session(connection_id, prepared.value().session, session);
  if (!authorized) {
    return send_error(connection_id, Uuid{}, authorized.outcome(), authorized.message());
  }
  model::GrantRecord* grant = registry_.find_grant(prepared.value().grant);
  if (grant == nullptr) {
    return send_error(connection_id, Uuid{}, Outcome::NotFound, "the grant is not registered");
  }
  const model::ContractRecord* contract = registry_.find_contract(grant->contract);
  if (contract == nullptr) {
    return send_error(connection_id, Uuid{}, Outcome::NotFound, "the grant references an unknown contract");
  }
  const int side = contract->side_of(session->cluster);
  if (side < 0) {
    return send_error(connection_id, Uuid{}, Outcome::Unauthorized, "the grant does not involve this cluster");
  }
  if (prepared.value().attempt != grant->attempt) {
    ++rejected_replays_;
    return send_error(connection_id, Uuid{}, Outcome::Replayed, "the acknowledgement names a different attempt");
  }
  if (grant->incarnations[static_cast<std::size_t>(side)] != session->incarnation ||
      grant->generations[static_cast<std::size_t>(side)] != session->generation) {
    ++rejected_replays_;
    return send_error(connection_id, Uuid{}, Outcome::Stale,
                      "the acknowledgement comes from a superseded incarnation or generation");
  }
  if (grant->state != model::GrantState::Preparing && grant->state != model::GrantState::Prepared) {
    return send_error(connection_id, Uuid{}, Outcome::Conflicting,
                      "the grant is no longer accepting prepare acknowledgements");
  }
  if (!prepared.value().accepted) {
    const Status aborted = abort_grant(grant->id, prepared.value().detail);
    if (!aborted) {
      return aborted;
    }
    return append_audit("agent", "refuse-grant", grant->id.to_string(), Outcome::Refused, prepared.value().detail);
  }
  auto pending_it = pending_.find(grant->id);
  if (pending_it == pending_.end()) {
    return send_error(connection_id, Uuid{}, Outcome::Indeterminate, "the grant flow is not tracked");
  }
  pending_it->second.prepared[static_cast<std::size_t>(side)] = true;
  grant->enforcement_digest[static_cast<std::size_t>(side)] = prepared.value().enforcement_digest;
  if (pending_it->second.prepared[0] && pending_it->second.prepared[1]) {
    return commit_grant(grant->id);
  }
  return Status::ok();
}

Status Coordinator::on_grant_committed(std::uint64_t connection_id, const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::GrantCommittedMessage> committed = wire::decode_grant_committed(reader);
  if (!committed) {
    ++rejected_frames_;
    return send_error(connection_id, Uuid{}, committed.status().outcome(), committed.status().message());
  }
  PeerSession* session = nullptr;
  const Status authorized = require_session(connection_id, committed.value().session, session);
  if (!authorized) {
    return send_error(connection_id, Uuid{}, authorized.outcome(), authorized.message());
  }
  model::GrantRecord* grant = registry_.find_grant(committed.value().grant);
  if (grant == nullptr) {
    return send_error(connection_id, Uuid{}, Outcome::NotFound, "the grant is not registered");
  }
  const model::ContractRecord* contract = registry_.find_contract(grant->contract);
  if (contract == nullptr) {
    return send_error(connection_id, Uuid{}, Outcome::NotFound, "the grant references an unknown contract");
  }
  const int side = contract->side_of(session->cluster);
  if (side < 0) {
    return send_error(connection_id, Uuid{}, Outcome::Unauthorized, "the grant does not involve this cluster");
  }
  if (committed.value().attempt != grant->attempt) {
    ++rejected_replays_;
    return send_error(connection_id, Uuid{}, Outcome::Replayed, "the acknowledgement names a different attempt");
  }
  if (grant->incarnations[static_cast<std::size_t>(side)] != session->incarnation ||
      grant->generations[static_cast<std::size_t>(side)] != session->generation) {
    ++rejected_replays_;
    return send_error(connection_id, Uuid{}, Outcome::Stale,
                      "the acknowledgement comes from a superseded incarnation or generation");
  }
  if (!committed.value().installed) {
    const Status aborted = abort_grant(grant->id, committed.value().detail);
    if (!aborted) {
      return aborted;
    }
    return append_audit("agent", "refuse-commit", grant->id.to_string(), Outcome::Refused, committed.value().detail);
  }
  grant->acknowledged[static_cast<std::size_t>(side)] = true;
  grant->enforcement_digest[static_cast<std::size_t>(side)] = committed.value().enforcement_digest;
  store::Mutation mutation;
  mutation.kind = store::MutationKind::GrantPut;
  mutation.grant = *grant;
  const Status persisted = append_mutation(mutation);
  if (!persisted) {
    return persisted;
  }
  if (grant->both_acknowledged()) {
    return finalise_grant(grant->id, clock_->now());
  }
  return Status::ok();
}

Status Coordinator::on_grant_aborted(std::uint64_t connection_id, const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::GrantAbortedMessage> aborted = wire::decode_grant_aborted(reader);
  if (!aborted) {
    ++rejected_frames_;
    return send_error(connection_id, Uuid{}, aborted.status().outcome(), aborted.status().message());
  }
  PeerSession* session = nullptr;
  const Status authorized = require_session(connection_id, aborted.value().session, session);
  if (!authorized) {
    return send_error(connection_id, Uuid{}, authorized.outcome(), authorized.message());
  }
  return abort_grant(aborted.value().grant, aborted.value().reason);
}

Status Coordinator::on_fence_ack(std::uint64_t connection_id, const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::FenceAckMessage> ack = wire::decode_fence_ack(reader);
  if (!ack) {
    ++rejected_frames_;
    return send_error(connection_id, Uuid{}, ack.status().outcome(), ack.status().message());
  }
  PeerSession* session = nullptr;
  const Status authorized = require_session(connection_id, ack.value().session, session);
  if (!authorized) {
    return send_error(connection_id, Uuid{}, authorized.outcome(), authorized.message());
  }
  for (const wire::FenceResult& result : ack.value().results) {
    const Status audited = append_audit("agent", "fence-ack",
                                        std::string("grant=") + result.grant.to_string(), result.outcome,
                                        std::string("cluster=") + session->cluster.str());
    if (!audited) {
      return audited;
    }
  }
  return Status::ok();
}

Status Coordinator::on_withdraw(std::uint64_t connection_id, const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::WithdrawMessage> withdraw = wire::decode_withdraw(reader);
  if (!withdraw) {
    ++rejected_frames_;
    return send_error(connection_id, Uuid{}, withdraw.status().outcome(), withdraw.status().message());
  }
  PeerSession* session = nullptr;
  const Status authorized = require_session(connection_id, withdraw.value().session, session);
  if (!authorized) {
    return send_error(connection_id, Uuid{}, authorized.outcome(), authorized.message());
  }
  if (session->role != wire::PeerRole::Agent || withdraw.value().cluster != session->cluster) {
    return send_error(connection_id, Uuid{}, Outcome::Unauthorized, "the withdrawal does not match this session");
  }
  model::ClusterRecord* cluster = registry_.find_cluster(session->cluster);
  if (cluster == nullptr) {
    return send_error(connection_id, Uuid{}, Outcome::NotFound, "the cluster is not registered");
  }
  if (withdraw.value().incarnation != cluster->incarnation || withdraw.value().generation < cluster->generation) {
    ++rejected_replays_;
    return send_error(connection_id, Uuid{}, Outcome::Stale, "the withdrawal comes from a superseded incarnation");
  }
  const std::size_t grants_before = registry_.grants().size();
  cluster->consent_withdrawn = true;
  cluster->last_seen = clock_->now();
  const Status fenced = fence_cluster(cluster->id, model::FenceTrigger::ClusterWithdrawal, cluster->incarnation,
                                      cluster->incarnation, cluster->generation);
  if (!fenced) {
    return fenced;
  }
  const model::ClusterRecord* updated = registry_.find_cluster(session->cluster);
  store::Mutation mutation;
  mutation.kind = store::MutationKind::ClusterPut;
  mutation.cluster = *updated;
  const Status persisted = append_mutation(mutation);
  if (!persisted) {
    return persisted;
  }
  std::uint64_t fenced_grants = 0;
  for (const auto& entry : registry_.grants()) {
    if (entry.second.state == model::GrantState::Fenced) {
      ++fenced_grants;
    }
  }
  (void)grants_before;
  wire::WithdrawAckMessage response;
  response.session = session->token;
  response.outcome = Outcome::Ok;
  response.fenced_grants = fenced_grants;
  response.detail = withdraw.value().reason;
  const Status audited = append_audit("agent", "withdraw-consent", session->cluster.str(), Outcome::Fenced,
                                      "the cluster withdrew consent; dependent grants were fenced");
  if (!audited) {
    return audited;
  }
  return send_to(connection_for(connection_id), wire::MessageType::WithdrawAck, response);
}

Status Coordinator::on_status_report(std::uint64_t connection_id, const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::StatusReportMessage> report = wire::decode_status_report(reader);
  if (!report) {
    ++rejected_frames_;
    return send_error(connection_id, Uuid{}, report.status().outcome(), report.status().message());
  }
  PeerSession* session = nullptr;
  const Status authorized = require_session(connection_id, report.value().session, session);
  if (!authorized) {
    return send_error(connection_id, Uuid{}, authorized.outcome(), authorized.message());
  }
  ++revalidations_;
  std::vector<GrantId> to_fence;
  for (auto& entry : registry_.grants()) {
    model::GrantRecord& grant = entry.second;
    const model::ContractRecord* contract = registry_.find_contract(grant.contract);
    if (contract == nullptr) {
      continue;
    }
    const int side = contract->side_of(session->cluster);
    if (side < 0) {
      continue;
    }
    const auto reported = std::find_if(report.value().grants.begin(), report.value().grants.end(),
                                       [&grant](const wire::GrantStatusEntry& candidate) {
                                         return candidate.grant == grant.id;
                                       });
    const bool enforcement_installed =
        reported != report.value().grants.end() && reported->attempt == grant.attempt &&
        (reported->state == model::GrantState::Committed || reported->state == model::GrantState::Active);
    const bool stale_enforcement =
        reported != report.value().grants.end() && reported->attempt != grant.attempt &&
        (reported->state == model::GrantState::Committed || reported->state == model::GrantState::Active);

    if (stale_enforcement) {
      to_fence.push_back(grant.id);
      continue;
    }
    if (enforcement_installed) {
      if (grant.incarnations[static_cast<std::size_t>(side)] != session->incarnation ||
          grant.generations[static_cast<std::size_t>(side)] != session->generation) {
        // The agent enforces a grant bound to a different incarnation: it must be fenced.
        to_fence.push_back(grant.id);
        continue;
      }
      if (!grant.acknowledged[static_cast<std::size_t>(side)]) {
        grant.acknowledged[static_cast<std::size_t>(side)] = true;
        grant.enforcement_digest[static_cast<std::size_t>(side)] = reported->enforcement_digest;
        store::Mutation mutation;
        mutation.kind = store::MutationKind::GrantPut;
        mutation.grant = grant;
        const Status persisted = append_mutation(mutation);
        if (!persisted) {
          return persisted;
        }
      }
      continue;
    }
    // The coordinator believes the grant is usable but the agent does not enforce it. The grant
    // is not usable until the agent installs it again, so it is withdrawn.
    if (grant.usable_state()) {
      grant.state = model::GrantState::Indeterminate;
      grant.note = "the cluster agent does not report an installed enforcement for this grant";
      store::Mutation mutation;
      mutation.kind = store::MutationKind::GrantPut;
      mutation.grant = grant;
      const Status persisted = append_mutation(mutation);
      if (!persisted) {
        return persisted;
      }
      to_fence.push_back(grant.id);
    }
  }
  if (!to_fence.empty()) {
    model::FencePlan plan;
    plan.trigger = model::FenceTrigger::GrantRevocation;
    plan.term = term_;
    plan.view_digest = registry_.digest();
    for (const GrantId& grant_id : to_fence) {
      model::FenceAction action;
      action.target = model::FenceTarget::Grant;
      action.grant = grant_id;
      const model::GrantRecord* grant = registry_.find_grant(grant_id);
      if (grant != nullptr) {
        action.contract = grant->contract;
      }
      action.reason = model::ReasonCode::GrantNeedsRevalidation;
      plan.actions.push_back(action);
    }
    for (const auto& entry : registry_.reservations()) {
      if (entry.second.released) {
        continue;
      }
      if (std::find(to_fence.begin(), to_fence.end(), entry.second.grant) == to_fence.end()) {
        continue;
      }
      model::FenceAction action;
      action.target = model::FenceTarget::Reservation;
      action.grant = entry.second.grant;
      action.reservation = entry.first;
      action.reason = model::ReasonCode::GrantNeedsRevalidation;
      plan.actions.push_back(action);
    }
    const Status applied = fence_plan_apply(plan, "coordinator");
    if (!applied) {
      return applied;
    }
  }
  // A grant that both sides report as installed but that the coordinator recorded as
  // indeterminate can now be finalised, because the *durable* record on both sides and the
  // coordinator's own intent agree on the same attempt.
  for (auto& entry : registry_.grants()) {
    model::GrantRecord& grant = entry.second;
    if (grant.state != model::GrantState::Indeterminate || !grant.both_acknowledged()) {
      continue;
    }
    const Status finalised = finalise_grant(grant.id, clock_->now());
    if (!finalised) {
      return finalised;
    }
  }
  return Status::ok();
}

void Coordinator::tick() {
  expire_grants();
  retry_pending_flows();
  const Status compacted = compact_if_needed();
  if (!compacted) {
    ICF_LOG_WARN("coordinator", "compaction failed");
  }
  const Timestamp now = clock_->now();
  if (config_.ping_interval.nanos() > 0) {
    for (const auto& entry : sessions_) {
      const PeerSession& session = entry.second;
      if (session.role != wire::PeerRole::Agent || !session.hello_complete) {
        continue;
      }
      wire::PingMessage ping;
      ping.sequence = Sequence(entry.first);
      ping.sent_at = now;
      (void)send_to(connection_for(entry.first), wire::MessageType::Ping, ping);
    }
  }
  (void)loop_.schedule(now.plus(kTickInterval), [this]() { tick(); });
}

void Coordinator::expire_grants() {
  const Timestamp now = clock_->now();
  std::vector<GrantId> expired;
  for (const auto& entry : registry_.grants()) {
    const model::GrantRecord& grant = entry.second;
    if (!grant.usable_state()) {
      continue;
    }
    if (now.unix_nanos() > grant.valid_until.unix_nanos()) {
      expired.push_back(grant.id);
    }
  }
  if (expired.empty()) {
    return;
  }
  model::FencePlan plan;
  plan.trigger = model::FenceTrigger::GrantExpiry;
  plan.term = term_;
  plan.view_digest = registry_.digest();
  for (const GrantId& grant_id : expired) {
    model::FenceAction action;
    action.target = model::FenceTarget::Grant;
    action.grant = grant_id;
    action.reason = model::ReasonCode::GrantExpired;
    plan.actions.push_back(action);
  }
  for (const auto& entry : registry_.reservations()) {
    if (entry.second.released) {
      continue;
    }
    if (std::find(expired.begin(), expired.end(), entry.second.grant) == expired.end()) {
      continue;
    }
    model::FenceAction action;
    action.target = model::FenceTarget::Reservation;
    action.grant = entry.second.grant;
    action.reservation = entry.first;
    action.reason = model::ReasonCode::GrantExpired;
    plan.actions.push_back(action);
  }
  (void)fence_plan_apply(plan, "coordinator");
  for (const GrantId& grant_id : expired) {
    model::GrantRecord* grant = registry_.find_grant(grant_id);
    if (grant == nullptr) {
      continue;
    }
    grant->state = model::GrantState::Expired;
    store::Mutation mutation;
    mutation.kind = store::MutationKind::GrantPut;
    mutation.grant = *grant;
    (void)append_mutation(mutation);
  }
}

void Coordinator::retry_pending_flows() {
  const Timestamp now = clock_->now();
  std::vector<GrantId> timed_out;
  for (auto& entry : pending_) {
    PendingGrant& pending = entry.second;
    for (std::size_t side = 0; side < model::kPartyCount; ++side) {
      if (!pending.targets[side].connected) {
        const model::GrantRecord* grant = registry_.find_grant(pending.grant);
        const model::ContractRecord* contract = grant == nullptr ? nullptr : registry_.find_contract(grant->contract);
        if (contract != nullptr) {
          const SendTarget target = target_for(contract->parties[side].cluster);
          if (target.connected) {
            pending.targets[side] = target;
          }
        }
      }
    }
    if (now.unix_nanos() > pending.deadline.unix_nanos() || pending.attempts >= limits::kMaxRevalidateAttempts) {
      timed_out.push_back(pending.grant);
      continue;
    }
    ++pending.attempts;
  }
  for (const GrantId& grant_id : timed_out) {
    (void)abort_grant(grant_id, "the grant flow did not complete within its deadline");
  }
  for (auto& entry : pending_) {
    PendingGrant& pending = entry.second;
    const model::GrantRecord* grant = registry_.find_grant(pending.grant);
    if (grant == nullptr) {
      continue;
    }
    if (grant->state != model::GrantState::Preparing) {
      continue;
    }
    for (std::size_t side = 0; side < model::kPartyCount; ++side) {
      if (!pending.targets[side].connected || pending.prepared[side]) {
        continue;
      }
      wire::PrepareGrantMessage message;
      message.session = pending.targets[side].token;
      message.grant = *grant;
      (void)send_to(connection_for(pending.targets[side].connection_id), wire::MessageType::PrepareGrant, message);
    }
  }
}

model::CoordinatorStatus Coordinator::status() const {
  model::CoordinatorStatus status;
  status.domain = config_.domain;
  status.incarnation = incarnation_;
  status.term = term_;
  status.started_at = started_at_;
  status.uptime_nanos = static_cast<std::uint64_t>(clock_->monotonic_nanos() < 0 ? 0 : clock_->monotonic_nanos());
  status.view_digest = registry_.digest();
  status.revision = recovery_.meta.revision;
  status.recovered_from_store = recovery_.recovered_from_store;
  status.recovered_records = recovery_.wal.records;
  status.truncations_recovered = recovery_.meta.truncations;
  const model::RegistryCounts counts = registry_.counts();
  status.clusters = counts.clusters;
  status.endpoints = counts.endpoints;
  status.links = counts.links;
  status.paths = counts.paths;
  status.contracts = counts.contracts;
  status.grants = counts.grants;
  status.reservations = counts.reservations;
  status.policies = counts.policies;
  status.audit = counts.audit;
  // Only cluster-agent sessions count as connected agents: an operator's observer session is not
  // a connected cluster, and reporting it as one would make "is every agent connected?" wrong.
  std::size_t connected_agents = 0;
  for (const auto& entry : sessions_) {
    if (entry.second.role == wire::PeerRole::Agent && entry.second.hello_complete) {
      ++connected_agents;
    }
  }
  status.connected_agents = connected_agents;
  status.commits = commits_;
  status.fences = fences_;
  status.refusals = refusals_;
  status.revalidations = revalidations_;
  status.rejected_replays = rejected_replays_;
  status.rejected_frames = rejected_frames_;
  status.store_path = store_.snapshot_path();
  return status;
}

Status Coordinator::on_query(std::uint64_t connection_id, const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::QueryMessage> query = wire::decode_query(reader);
  if (!query) {
    ++rejected_frames_;
    return send_error(connection_id, Uuid{}, query.status().outcome(), query.status().message());
  }
  const Status end = reader.expect_end();
  if (!end) {
    ++rejected_frames_;
    return send_error(connection_id, query.value().request, Outcome::Invalid, end.message());
  }
  wire::QueryResultMessage result;
  const Status handled = handle_query(query.value(), result);
  if (!handled) {
    result.outcome = handled.outcome();
    result.detail = handled.message();
  }
  return send_to(connection_for(connection_id), wire::MessageType::QueryResult, result);
}

Status Coordinator::handle_query(const wire::QueryMessage& query, wire::QueryResultMessage& result) const {
  result.request = query.request;
  result.kind = query.kind;
  result.outcome = Outcome::Ok;
  const std::size_t limit = query.limit == 0 ? 256 : query.limit;
  switch (query.kind) {
    case wire::QueryKind::Status:
      result.status = status();
      break;
    case wire::QueryKind::ListClusters: {
      for (const auto& entry : registry_.clusters()) {
        if (result.clusters.size() >= limit) {
          break;
        }
        if (!query.cluster.empty() && entry.first != query.cluster) {
          continue;
        }
        result.clusters.push_back(entry.second);
      }
      break;
    }
    case wire::QueryKind::ShowCluster: {
      const model::ClusterRecord* cluster = registry_.find_cluster(query.cluster);
      if (cluster == nullptr) {
        return not_found("cluster is not registered");
      }
      result.clusters.push_back(*cluster);
      break;
    }
    case wire::QueryKind::ListLinks: {
      for (const auto& entry : registry_.links()) {
        if (result.links.size() >= limit) {
          break;
        }
        result.links.push_back(entry.second);
      }
      break;
    }
    case wire::QueryKind::ListPaths: {
      for (const auto& entry : registry_.paths()) {
        if (result.paths.size() >= limit) {
          break;
        }
        result.paths.push_back(entry.second);
      }
      break;
    }
    case wire::QueryKind::ListPolicies: {
      for (const auto& entry : registry_.policies()) {
        if (result.policies.size() >= limit) {
          break;
        }
        result.policies.push_back(entry.second);
      }
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
        return not_found("contract is not registered");
      }
      result.contracts.push_back(*contract);
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
        return not_found("grant is not registered");
      }
      result.grants.push_back(*grant);
      break;
    }
    case wire::QueryKind::ListReservations: {
      for (const auto& entry : registry_.reservations()) {
        if (result.reservations.size() >= limit) {
          break;
        }
        result.reservations.push_back(entry.second);
      }
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
    case wire::QueryKind::Decide: {
      model::DecisionQuery decision_query;
      decision_query.source = query.endpoint;
      decision_query.target = query.endpoint_b;
      decision_query.requested_capacity = query.capacity;
      decision_query.allow_degraded = query.allow_degraded;
      decision_query.at = clock_->now();
      decision_query.expect_source_generation = query.expect_source_generation;
      decision_query.source_generation = query.source_generation;
      decision_query.expect_target_generation = query.expect_target_generation;
      decision_query.target_generation = query.target_generation;
      EngineView view;
      view.term = term_;
      view.incarnation = incarnation_;
      view.now = clock_->now();
      model::Decision decision = decide(registry_, decision_query, view);
      result.outcome = decision.outcome;
      result.detail = decision.detail;
      result.decision = std::move(decision);
      break;
    }
    case wire::QueryKind::FencePlan: {
      const model::ClusterRecord* cluster = registry_.find_cluster(query.cluster);
      if (cluster == nullptr) {
        return not_found("cluster is not registered");
      }
      model::FenceTrigger trigger = model::FenceTrigger::Manual;
      if (query.limit == 1) {
        trigger = model::FenceTrigger::ClusterReincarnation;
      } else if (query.limit == 2) {
        trigger = model::FenceTrigger::ClusterWithdrawal;
      } else if (query.limit == 3) {
        trigger = model::FenceTrigger::PolicyGenerationChange;
      } else if (query.limit == 4) {
        trigger = model::FenceTrigger::CoordinatorReincarnation;
      }
      result.fence_plan = plan_fence(registry_, trigger, cluster->id, cluster->incarnation, cluster->incarnation,
                                     cluster->generation, term_);
      break;
    }
    case wire::QueryKind::Accounting: {
      for (const auto& entry : registry_.reservations()) {
        if (result.accounting.size() >= limit) {
          break;
        }
        model::AccountingEntry accounting;
        accounting.grant = entry.second.grant;
        const model::GrantRecord* grant = registry_.find_grant(entry.second.grant);
        if (grant != nullptr) {
          accounting.contract = grant->contract;
        }
        accounting.endpoint = entry.second.endpoint;
        accounting.cluster = entry.second.cluster;
        accounting.reserved = entry.second.amount;
        accounting.released = entry.second.released ? entry.second.amount : CapacityUnits{};
        accounting.closed = entry.second.released;
        result.accounting.push_back(accounting);
      }
      break;
    }
  }
  return Status::ok();
}

Status Coordinator::propose_contract_to_agents(const model::ContractRecord& contract) {
  bool all_connected = true;
  for (std::size_t side = 0; side < model::kPartyCount; ++side) {
    const SendTarget target = target_for(contract.parties[side].cluster);
    if (!target.connected) {
      all_connected = false;
      continue;
    }
    wire::ProposeContractMessage message;
    message.session = target.token;
    message.contract = contract.id;
    message.terms = model::ContractTerms{};
    message.terms.parties = contract.parties;
    message.terms.capacity = contract.capacity;
    message.terms.lease_duration = contract.lease_duration;
    message.terms.proposed_at = contract.created_at;
    for (std::size_t index = 0; index < model::kPartyCount; ++index) {
      const model::ClusterRecord* cluster = registry_.find_cluster(contract.parties[index].cluster);
      if (cluster == nullptr) {
        return not_found("a contracting cluster is not registered");
      }
      message.terms.incarnations[index] = cluster->incarnation;
      message.terms.generations[index] = cluster->generation;
      message.terms.policies[index] = cluster->policy_generation;
    }
    message.attempt = AttemptId::random(rng_);
    const Status sent = send_to(connection_for(target.connection_id), wire::MessageType::ProposeContract, message);
    if (!sent) {
      return sent;
    }
  }
  if (!all_connected) {
    return Status::make(Outcome::Unreachable,
                        "a contracting cluster agent is not connected; the contract stays proposed");
  }
  return Status::ok();
}

Status Coordinator::apply_contract_proposal(const wire::AdminMessage& request, wire::AdminResultMessage& result) {
  if (request.cluster_id.empty() || request.endpoint.empty() || request.cluster_b.empty() ||
      request.endpoint_b.empty()) {
    result.outcome = Outcome::Invalid;
    result.detail = "a contract requires two clusters and two endpoint scopes";
    return invalid(result.detail);
  }
  const model::ClusterRecord* source = registry_.find_cluster(request.cluster_id);
  const model::ClusterRecord* target = registry_.find_cluster(request.cluster_b);
  if (source == nullptr || target == nullptr) {
    result.outcome = Outcome::NotFound;
    result.detail = "both clusters must be registered before a contract can be proposed";
    return not_found(result.detail);
  }
  model::ContractRecord contract;
  contract.id = ContractId::random(rng_);
  contract.parties[0].cluster = source->id;
  contract.parties[0].domain = source->domain;
  contract.parties[1].cluster = target->id;
  contract.parties[1].domain = target->domain;
  contract.parties[0].endpoint = request.endpoint;
  contract.parties[1].endpoint = request.endpoint_b;
  contract.capacity = request.capacity.value() == 0 ? CapacityUnits(1) : request.capacity;
  contract.lease_duration = request.lease_duration.is_zero() ? config_.default_lease : request.lease_duration;
  contract.state = model::ContractState::Proposed;
  contract.created_at = clock_->now();
  contract.updated_at = contract.created_at;
  contract.provenance.source = model::EvidenceSource::AdminConfigured;
  contract.provenance.verification = model::VerificationState::Verified;
  contract.provenance.observed_at = contract.created_at;
  model::ContractTerms terms;
  terms.parties = contract.parties;
  terms.capacity = contract.capacity;
  terms.lease_duration = contract.lease_duration;
  terms.proposed_at = contract.created_at;
  terms.incarnations[0] = source->incarnation;
  terms.incarnations[1] = target->incarnation;
  terms.generations[0] = source->generation;
  terms.generations[1] = target->generation;
  terms.policies[0] = source->policy_generation;
  terms.policies[1] = target->policy_generation;
  const Status valid_terms = terms.validate();
  if (!valid_terms) {
    result.outcome = valid_terms.outcome();
    result.detail = valid_terms.message();
    return valid_terms;
  }
  contract.terms_digest = terms.digest();
  const Status stored = registry_.put_contract(contract);
  if (!stored) {
    result.outcome = stored.outcome();
    result.detail = stored.message();
    return stored;
  }
  store::Mutation mutation;
  mutation.kind = store::MutationKind::ContractPut;
  mutation.contract = contract;
  const Status persisted = append_mutation(mutation);
  if (!persisted) {
    result.outcome = persisted.outcome();
    result.detail = persisted.message();
    return persisted;
  }
  const Status audited = append_audit("operator", "propose-contract", contract.id.to_string(), Outcome::Ok,
                                      "two-sided consent requested");
  if (!audited) {
    result.outcome = audited.outcome();
    result.detail = audited.message();
    return audited;
  }
  const Status proposed = propose_contract_to_agents(contract);
  if (!proposed) {
    result.outcome = proposed.outcome();
    result.detail = proposed.message();
    return proposed;
  }
  result.outcome = Outcome::Ok;
  result.contract = contract.id;
  result.detail = std::string("contract ") + contract.id.to_string() + " proposed to both authority domains";
  return Status::ok();
}

Status Coordinator::apply_grant_issue(const wire::AdminMessage& request, wire::AdminResultMessage& result) {
  model::ContractRecord* contract = registry_.find_contract(request.contract);
  if (contract == nullptr) {
    result.outcome = Outcome::NotFound;
    result.detail = "the contract is not registered";
    return not_found(result.detail);
  }
  if (contract->state != model::ContractState::Consented && contract->state != model::ContractState::Active) {
    result.outcome = Outcome::Incomplete;
    result.detail = "both authority domains must consent before a grant can be issued";
    return Status::make(Outcome::Incomplete, result.detail);
  }
  model::GrantRecord grant;
  grant.id = GrantId::random(rng_);
  grant.contract = contract->id;
  grant.terms_digest = contract->terms_digest;
  grant.coordinator_term = term_;
  grant.coordinator = incarnation_;
  grant.attempt = AttemptId::random(rng_);
  grant.capacity = request.capacity.value() == 0 ? contract->capacity : request.capacity;
  if (grant.capacity.value() > contract->capacity.value()) {
    result.outcome = Outcome::CapacityExceeded;
    result.detail = "the requested capacity exceeds the contract capacity";
    return Status::make(Outcome::CapacityExceeded, result.detail);
  }
  grant.issued_at = clock_->now();
  grant.valid_until = grant.issued_at.plus(contract->lease_duration);
  grant.state = model::GrantState::Preparing;
  for (std::size_t side = 0; side < model::kPartyCount; ++side) {
    const model::ClusterRecord* cluster = registry_.find_cluster(contract->parties[side].cluster);
    if (cluster == nullptr) {
      result.outcome = Outcome::NotFound;
      result.detail = "a contracting cluster is not registered";
      return not_found(result.detail);
    }
    grant.incarnations[side] = cluster->incarnation;
    grant.generations[side] = cluster->generation;
    grant.policies[side] = cluster->policy_generation;
  }
  const Status stored = registry_.put_grant(grant);
  if (!stored) {
    result.outcome = stored.outcome();
    result.detail = stored.message();
    return stored;
  }
  const Status prepared = prepare_grant(grant);
  if (!prepared) {
    result.outcome = prepared.outcome();
    result.detail = prepared.message();
    return prepared;
  }
  result.outcome = Outcome::Ok;
  result.contract = grant.contract;
  result.grant = grant.id;
  result.detail = std::string("grant ") + grant.id.to_string() + " is being prepared on both sides";
  return Status::ok();
}

Status Coordinator::apply_grant_revalidation(const wire::AdminMessage& request, wire::AdminResultMessage& result) {
  model::GrantRecord* grant = registry_.find_grant(request.grant);
  if (grant == nullptr) {
    result.outcome = Outcome::NotFound;
    result.detail = "the grant is not registered";
    return not_found(result.detail);
  }
  if (grant->state == model::GrantState::Fenced) {
    result.outcome = Outcome::Fenced;
    result.detail = "a fenced grant is never revived; issue a new grant instead";
    return Status::make(Outcome::Fenced, result.detail);
  }
  grant->attempt = AttemptId::random(rng_);
  grant->coordinator_term = term_;
  grant->coordinator = incarnation_;
  grant->issued_at = clock_->now();
  const model::ContractRecord* contract = registry_.find_contract(grant->contract);
  if (contract == nullptr) {
    result.outcome = Outcome::NotFound;
    result.detail = "the grant references an unknown contract";
    return not_found(result.detail);
  }
  grant->valid_until = grant->issued_at.plus(contract->lease_duration);
  grant->acknowledged = {false, false};
  grant->state = model::GrantState::Preparing;
  grant->note = "revalidation requested after a superseding change";
  const Status prepared = prepare_grant(*grant);
  if (!prepared) {
    result.outcome = prepared.outcome();
    result.detail = prepared.message();
    return prepared;
  }
  result.outcome = Outcome::Ok;
  result.contract = grant->contract;
  result.grant = grant->id;
  result.detail = "grant revalidation started with a fresh attempt identifier";
  return Status::ok();
}

Status Coordinator::apply_consent_change(const wire::AdminMessage& request, wire::AdminResultMessage& result,
                                         bool withdraw) {
  model::ClusterRecord* cluster = registry_.find_cluster(request.cluster_id);
  if (cluster == nullptr) {
    result.outcome = Outcome::NotFound;
    result.detail = "the cluster is not registered";
    return not_found(result.detail);
  }
  cluster->consent_withdrawn = withdraw;
  const Status fenced =
      withdraw ? fence_cluster(cluster->id, model::FenceTrigger::ClusterWithdrawal, cluster->incarnation,
                               cluster->incarnation, cluster->generation)
               : Status::ok();
  if (!fenced) {
    result.outcome = fenced.outcome();
    result.detail = fenced.message();
    return fenced;
  }
  store::Mutation mutation;
  mutation.kind = store::MutationKind::ClusterPut;
  mutation.cluster = *registry_.find_cluster(request.cluster_id);
  const Status persisted = append_mutation(mutation);
  if (!persisted) {
    result.outcome = persisted.outcome();
    result.detail = persisted.message();
    return persisted;
  }
  const Status audited = append_audit("operator", withdraw ? "withdraw-consent" : "restore-consent",
                                      request.cluster_id.str(), Outcome::Ok, request.reason);
  if (!audited) {
    result.outcome = audited.outcome();
    result.detail = audited.message();
    return audited;
  }
  result.outcome = Outcome::Ok;
  result.detail = withdraw ? "consent withdrawn and dependent grants fenced" : "consent restored";
  return Status::ok();
}

Status Coordinator::apply_conflict_resolution(const wire::AdminMessage& request, wire::AdminResultMessage& result) {
  model::ClusterRecord* cluster = registry_.find_cluster(request.cluster_id);
  if (cluster == nullptr) {
    result.outcome = Outcome::NotFound;
    result.detail = "the cluster is not registered";
    return not_found(result.detail);
  }
  if (!cluster->generation_conflict) {
    result.outcome = Outcome::Invalid;
    result.detail = "the cluster has no unresolved generation conflict";
    return invalid(result.detail);
  }
  if (request.generation <= cluster->generation) {
    result.outcome = Outcome::Invalid;
    result.detail = "the resolving generation must be greater than the conflicting generation";
    return invalid(result.detail);
  }
  cluster->generation_conflict = false;
  cluster->conflicting_generation.reset();
  cluster->generation = request.generation;
  const Status fenced = fence_cluster(cluster->id, model::FenceTrigger::Manual, cluster->incarnation,
                                      cluster->incarnation, cluster->generation);
  if (!fenced) {
    result.outcome = fenced.outcome();
    result.detail = fenced.message();
    return fenced;
  }
  store::Mutation mutation;
  mutation.kind = store::MutationKind::ClusterPut;
  mutation.cluster = *registry_.find_cluster(request.cluster_id);
  const Status persisted = append_mutation(mutation);
  if (!persisted) {
    result.outcome = persisted.outcome();
    result.detail = persisted.message();
    return persisted;
  }
  const Status audited = append_audit("operator", "resolve-conflict", request.cluster_id.str(), Outcome::Ok,
                                      request.reason);
  if (!audited) {
    result.outcome = audited.outcome();
    result.detail = audited.message();
    return audited;
  }
  result.outcome = Outcome::Ok;
  result.detail = "generation conflict resolved at generation " + std::to_string(request.generation.value());
  return Status::ok();
}

Status Coordinator::handle_admin(const wire::AdminMessage& request, wire::AdminResultMessage& result) {
  result.request = request.request;
  result.outcome = Outcome::Ok;
  Status status = Status::ok();
  switch (request.action) {
    case wire::AdminAction::UpsertCluster: {
      if (!request.cluster.has_value()) {
        return invalid("upsert-cluster requires a cluster record");
      }
      model::ClusterRecord record = *request.cluster;
      if (record.domain.empty()) {
        record.domain = config_.domain;
      }
      record.revision = Revision(registry_.counts().clusters + registry_.counts().contracts);
      record.provenance.source = model::EvidenceSource::AdminConfigured;
      record.provenance.verification = model::VerificationState::Verified;
      record.provenance.observed_at = clock_->now();
      status = registry_.put_cluster(record);
      if (status) {
        store::Mutation mutation;
        mutation.kind = store::MutationKind::ClusterPut;
        mutation.cluster = *registry_.find_cluster(record.id);
        status = append_mutation(mutation);
      }
      if (status) {
        status = append_audit("operator", "upsert-cluster", record.id.str(), Outcome::Ok, "administrative record");
      }
      break;
    }
    case wire::AdminAction::DeleteCluster: {
      status = registry_.erase_cluster(request.cluster_id);
      if (status) {
        store::Mutation mutation;
        mutation.kind = store::MutationKind::ClusterErase;
        mutation.cluster.id = request.cluster_id;
        status = append_mutation(mutation);
      }
      break;
    }
    case wire::AdminAction::SetClusterState: {
      model::ClusterRecord* cluster = registry_.find_cluster(request.cluster_id);
      if (cluster == nullptr) {
        return not_found("the cluster is not registered");
      }
      cluster->state = request.cluster_state;
      if (cluster->state == model::ClusterState::Retired) {
        status = fence_cluster(cluster->id, model::FenceTrigger::Manual, cluster->incarnation, cluster->incarnation,
                               cluster->generation);
      }
      if (status) {
        store::Mutation mutation;
        mutation.kind = store::MutationKind::ClusterPut;
        mutation.cluster = *registry_.find_cluster(request.cluster_id);
        status = append_mutation(mutation);
      }
      break;
    }
    case wire::AdminAction::UpsertLink: {
      if (!request.link.has_value()) {
        return invalid("upsert-link requires a link record");
      }
      model::LinkRecord record = *request.link;
      record.revision = Revision(registry_.counts().links);
      record.provenance.source = model::EvidenceSource::AdminConfigured;
      record.provenance.verification = model::VerificationState::Verified;
      record.provenance.observed_at = clock_->now();
      if (!model::link_kind_supported(record.kind)) {
        result.outcome = Outcome::Unsupported;
        result.detail = std::string("link kind is not supported by this runtime: ") +
                        model::link_kind_support_note(record.kind);
        return unsupported(result.detail);
      }
      if (record.state == model::LinkState::Unknown && record.kind == model::LinkKind::SyntheticModel) {
        record.state = model::LinkState::Up;
      }
      status = registry_.put_link(record);
      if (status) {
        store::Mutation mutation;
        mutation.kind = store::MutationKind::LinkPut;
        mutation.link = *registry_.find_link(record.id);
        status = append_mutation(mutation);
      }
      if (status) {
        registry_.recompute_path_states();
        status = append_audit("operator", "upsert-link", record.id.str(), Outcome::Ok,
                              model::link_kind_support_note(record.kind));
      }
      break;
    }
    case wire::AdminAction::SetLinkState: {
      model::LinkRecord* link = registry_.links().find(request.edge) == registry_.links().end()
                                    ? nullptr
                                    : &registry_.links()[request.edge];
      if (link == nullptr) {
        return not_found("the link is not registered");
      }
      link->state = request.link_state;
      link->provenance.observed_at = clock_->now();
      store::Mutation mutation;
      mutation.kind = store::MutationKind::LinkPut;
      mutation.link = *link;
      status = append_mutation(mutation);
      if (status) {
        registry_.recompute_path_states();
        for (const auto& entry : registry_.paths()) {
          store::Mutation path_mutation;
          path_mutation.kind = store::MutationKind::PathPut;
          path_mutation.path = entry.second;
          status = append_mutation(path_mutation);
          if (!status) {
            break;
          }
        }
      }
      break;
    }
    case wire::AdminAction::DeleteLink: {
      status = registry_.erase_link(request.edge);
      if (status) {
        store::Mutation mutation;
        mutation.kind = store::MutationKind::LinkErase;
        mutation.link.id = request.edge;
        status = append_mutation(mutation);
      }
      break;
    }
    case wire::AdminAction::UpsertPath: {
      if (!request.path.has_value()) {
        return invalid("upsert-path requires a path record");
      }
      model::PathRecord record = *request.path;
      record.revision = Revision(registry_.counts().paths);
      record.provenance.source = model::EvidenceSource::DerivedFromTopology;
      record.provenance.verification = model::VerificationState::Verified;
      record.provenance.observed_at = clock_->now();
      status = registry_.put_path(record);
      if (status) {
        registry_.recompute_path_states();
        const model::PathRecord* stored = registry_.find_path(record.id);
        store::Mutation mutation;
        mutation.kind = store::MutationKind::PathPut;
        mutation.path = *stored;
        status = append_mutation(mutation);
      }
      break;
    }
    case wire::AdminAction::DeletePath: {
      status = registry_.erase_path(request.edge.empty() ? PathId{} : PathId::unchecked(request.edge.str()));
      if (status) {
        store::Mutation mutation;
        mutation.kind = store::MutationKind::PathErase;
        mutation.path.id = PathId::unchecked(request.edge.str());
        status = append_mutation(mutation);
      }
      break;
    }
    case wire::AdminAction::UpsertPolicy: {
      if (!request.policy.has_value()) {
        return invalid("upsert-policy requires a policy rule");
      }
      model::PolicyRule rule = *request.policy;
      if (rule.owner.empty()) {
        rule.owner = config_.domain;
      }
      rule.revision = Revision(registry_.counts().policies);
      rule.provenance.source = model::EvidenceSource::AdminConfigured;
      rule.provenance.verification = model::VerificationState::Verified;
      rule.provenance.observed_at = clock_->now();
      status = registry_.put_policy(rule);
      if (status) {
        store::Mutation mutation;
        mutation.kind = store::MutationKind::PolicyPut;
        mutation.policy = rule;
        status = append_mutation(mutation);
      }
      if (status) {
        // A policy change that names a cluster invalidates the grants bound to the old policy
        // generation: the policy generation is what the consent was bound to.
        for (const ClusterId& named : {rule.cluster_a, rule.cluster_b}) {
          if (named.empty()) {
            continue;
          }
          status = fence_cluster(named, model::FenceTrigger::PolicyGenerationChange, IncarnationId{},
                                 IncarnationId{}, Generation{});
          if (!status) {
            break;
          }
        }
      }
      if (status) {
        status = append_audit("operator", "upsert-policy", rule.id, Outcome::Ok,
                              rule.allow ? "allow rule" : "refuse rule");
      }
      break;
    }
    case wire::AdminAction::DeletePolicy: {
      status = registry_.erase_policy(request.policy_id);
      if (status) {
        store::Mutation mutation;
        mutation.kind = store::MutationKind::PolicyErase;
        mutation.policy.id = request.policy_id;
        status = append_mutation(mutation);
      }
      break;
    }
    case wire::AdminAction::WithdrawConsent:
      return apply_consent_change(request, result, true);
    case wire::AdminAction::RestoreConsent:
      return apply_consent_change(request, result, false);
    case wire::AdminAction::ResolveConflict:
      return apply_conflict_resolution(request, result);
    case wire::AdminAction::AuthorizeContract:
      return apply_contract_proposal(request, result);
    case wire::AdminAction::IssueGrant:
      return apply_grant_issue(request, result);
    case wire::AdminAction::RevalidateGrant:
      return apply_grant_revalidation(request, result);
    case wire::AdminAction::FenceGrant: {
      model::GrantRecord* grant = registry_.find_grant(request.grant);
      if (grant == nullptr) {
        return not_found("the grant is not registered");
      }
      model::FencePlan plan;
      plan.trigger = model::FenceTrigger::GrantRevocation;
      plan.term = term_;
      plan.view_digest = registry_.digest();
      model::FenceAction action;
      action.target = model::FenceTarget::Grant;
      action.grant = grant->id;
      action.contract = grant->contract;
      action.reason = model::ReasonCode::GrantFenced;
      plan.actions.push_back(action);
      for (const auto& entry : registry_.reservations()) {
        if (entry.second.grant != grant->id || entry.second.released) {
          continue;
        }
        model::FenceAction release;
        release.target = model::FenceTarget::Reservation;
        release.grant = entry.second.grant;
        release.reservation = entry.first;
        release.reason = model::ReasonCode::GrantFenced;
        plan.actions.push_back(release);
      }
      status = fence_plan_apply(plan, "operator");
      break;
    }
    case wire::AdminAction::ReloadStore:
      result.outcome = Outcome::Unsupported;
      result.detail = "the store is opened once during startup; restart the coordinator to reload it";
      return unsupported(result.detail);
  }

  result.view_digest = registry_.digest();
  if (!status) {
    result.outcome = status.outcome();
    if (result.detail.empty()) {
      result.detail = status.message();
    }
    return status;
  }
  result.outcome = Outcome::Ok;
  return Status::ok();
}

Status Coordinator::on_admin(std::uint64_t connection_id, const wire::Frame& frame) {
  ByteReader reader(frame.payload);
  Result<wire::AdminMessage> request = wire::decode_admin(reader);
  if (!request) {
    ++rejected_frames_;
    return send_error(connection_id, Uuid{}, request.status().outcome(), request.status().message());
  }
  const PeerSession* session = session_for(connection_id);
  if (session != nullptr && session->role == wire::PeerRole::Agent) {
    ++rejected_replays_;
    return send_error(connection_id, request.value().request, Outcome::Unauthorized,
                      "an agent session may not perform coordinator administration");
  }
  wire::AdminResultMessage result;
  const Status handled = handle_admin(request.value(), result);
  if (!handled) {
    result.outcome = handled.outcome();
    if (result.detail.empty()) {
      result.detail = handled.message();
    }
  }
  result.view_digest = registry_.digest();
  return send_to(connection_for(connection_id), wire::MessageType::AdminResult, result);
}

}  // namespace icf::runtime


