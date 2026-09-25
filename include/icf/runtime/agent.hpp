// Inter-Cluster Fabric - cluster-side agent.
//
// The agent owns one cluster identity. It holds its own incarnation and generation, its own
// fencing term, its own durable enforcement records, and its own decision about whether to
// consent to a contract. A grant only becomes enforceable here after this agent has accepted the
// terms, prepared the exact attempt, and committed it; anything recovered from disk is fenced
// until the coordinator revalidates it under the current term.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "icf/core/rng.hpp"
#include "icf/core/time.hpp"
#include "icf/net/reactor.hpp"
#include "icf/runtime/engine.hpp"
#include "icf/store/durable_store.hpp"
#include "icf/wire/messages.hpp"

namespace icf::runtime {

class Agent {
 public:
  struct Config {
    ClusterId cluster;
    AuthorityDomainId domain;
    Generation generation;
    PolicyGeneration policy_generation = PolicyGeneration(1);
    model::ClusterState state = model::ClusterState::Active;
    std::vector<model::EndpointRecord> endpoints;
    std::string coordinator_host = "127.0.0.1";
    std::uint16_t coordinator_port = 0;
    std::string state_directory;
    std::string channel_key;
    std::string control_address = "127.0.0.1";
    std::uint16_t control_port = 0;
    bool durable = true;
    Duration connect_deadline = Duration::from_millis(limits::kDefaultConnectDeadlineMillis);
    Duration handshake_deadline = Duration::from_millis(limits::kDefaultHandshakeDeadlineMillis);
    Duration reconnect_backoff = Duration::from_millis(limits::kDefaultRetryBackoffMillis);
    Duration reconnect_backoff_max = Duration::from_millis(limits::kMaxRetryBackoffMillis);
    Duration tick_interval = Duration::from_millis(500);
    std::uint64_t compact_bytes = 2ull << 20;
    std::uint64_t compact_records = 8192;
    std::string readiness_file;
    // Test hook: refuse to enforce anything until a coordinator handshake completes. Production
    // default is true; a false value is only used to exercise the "no authorization without the
    // coordinator" path.
    bool require_coordinator = true;
  };

  [[nodiscard]] static Result<std::unique_ptr<Agent>> create(Config config, const Clock& clock);
  ~Agent();
  Agent(const Agent&) = delete;
  Agent& operator=(const Agent&) = delete;

  [[nodiscard]] Status start();
  [[nodiscard]] Status serve();
  void stop() noexcept;

  [[nodiscard]] std::uint16_t control_port() const noexcept { return control_port_; }
  [[nodiscard]] const model::Registry& registry() const noexcept { return registry_; }
  [[nodiscard]] Term local_term() const noexcept { return term_; }
  [[nodiscard]] IncarnationId incarnation() const noexcept { return incarnation_; }
  [[nodiscard]] Generation generation() const noexcept { return generation_; }
  [[nodiscard]] model::CoordinatorStatus status() const;
  [[nodiscard]] bool coordinator_connected() const noexcept { return coordinator_connected_; }

  // Local control surface, also reachable over the control channel.
  [[nodiscard]] Status set_cluster_state(model::ClusterState state);
  [[nodiscard]] Status bump_generation(const std::string& reason);
  [[nodiscard]] Status set_policy_generation(PolicyGeneration generation);
  [[nodiscard]] Status withdraw_consent(const std::string& reason);
  [[nodiscard]] Status fence_local_grant(const GrantId& grant, const std::string& reason);
  [[nodiscard]] Status upsert_endpoint(model::EndpointRecord endpoint);
  [[nodiscard]] Status update_from_admin(const wire::AdminMessage& request, wire::AdminResultMessage& result);
  [[nodiscard]] Status handle_query_local(const wire::QueryMessage& query, wire::QueryResultMessage& result) const;

  // Message handling entry point; exposed so tests can drive the state machine directly.
  [[nodiscard]] Status handle_message(std::uint64_t connection_id, const wire::Frame& frame);
  void handle_disconnect(std::uint64_t connection_id);
  void tick();

  // The agent's own answer to "may the local side use this grant right now". Independent of the
  // coordinator: it re-checks incarnation, generation, policy generation, term, lease, and the
  // local consent that the grant is bound to.
  [[nodiscard]] Outcome local_enforcement_outcome(const GrantId& grant) const;
  [[nodiscard]] std::size_t enforced_grant_count() const;

 private:
  Agent(Config config, const Clock& clock);

  struct Role {
    bool observer = false;
    bool hello_complete = false;
    SessionToken token;
    ClusterId cluster;
    std::uint64_t connection_id = 0;
  };

  [[nodiscard]] Status load_state();
  [[nodiscard]] Status begin_incarnation();
  [[nodiscard]] Status listen_control();
  [[nodiscard]] Status append_mutation(const store::Mutation& mutation);
  [[nodiscard]] Status append_audit(std::string action, std::string subject, Outcome outcome, std::string detail);
  [[nodiscard]] Status persist_cluster();
  [[nodiscard]] Status connect_to_coordinator();
  [[nodiscard]] Status send_to_coordinator(wire::MessageType type, const std::vector<std::byte>& payload);
  template <class Message>
  [[nodiscard]] Status send_message(wire::MessageType type, const Message& message);
  [[nodiscard]] const model::ClusterRecord* local_cluster() const;
  [[nodiscard]] bool grant_enforceable(const model::GrantRecord& grant) const;
  [[nodiscard]] Status reevaluate_enforcement(const std::string& reason);
  [[nodiscard]] Status fence_not_revalidated(Term coordinator_term);

  [[nodiscard]] Status on_hello_ack(const wire::Frame& frame);
  [[nodiscard]] Status on_report_ack(const wire::Frame& frame);
  [[nodiscard]] Status on_propose_contract(const wire::Frame& frame);
  [[nodiscard]] Status on_prepare_grant(const wire::Frame& frame);
  [[nodiscard]] Status on_commit_grant(const wire::Frame& frame);
  [[nodiscard]] Status on_abort_grant(const wire::Frame& frame);
  [[nodiscard]] Status on_fence(const wire::Frame& frame);
  [[nodiscard]] Status on_status_request(const wire::Frame& frame);
  [[nodiscard]] Status on_ping(const wire::Frame& frame);
  [[nodiscard]] Status on_query(std::uint64_t connection_id, const wire::Frame& frame);
  [[nodiscard]] Status on_admin(std::uint64_t connection_id, const wire::Frame& frame);
  [[nodiscard]] Status on_control_hello(std::uint64_t connection_id, const wire::Frame& frame);
  [[nodiscard]] Status send_error_to(std::uint64_t connection_id, const Uuid& request, Outcome outcome,
                                     const std::string& detail);
  [[nodiscard]] std::vector<std::byte> channel_key() const;
  [[nodiscard]] Status report_cluster();

  Config config_;
  const Clock* clock_;
  store::DurableStore store_;
  store::DurableStore::Recovery recovery_;
  model::Registry registry_;
  Term term_;
  IncarnationId incarnation_;
  Generation generation_;
  PolicyGeneration policy_generation_;
  model::ClusterState cluster_state_ = model::ClusterState::Unknown;
  Timestamp started_at_{};
  net::EventLoop loop_;
  net::TcpListener control_listener_;
  std::uint16_t control_port_ = 0;
  std::map<std::uint64_t, Role> roles_;
  std::uint64_t coordinator_connection_ = 0;
  SessionToken coordinator_session_;
  Term coordinator_term_;
  IncarnationId coordinator_incarnation_;
  bool coordinator_connected_ = false;
  bool handshake_complete_ = false;
  Duration backoff_;
  Rng rng_;
  std::uint64_t enforced_ = 0;
  std::uint64_t fences_ = 0;
  std::uint64_t refusals_ = 0;
  std::uint64_t revalidations_ = 0;
  std::uint64_t rejected_frames_ = 0;
  std::uint64_t errors_received_ = 0;
  std::uint64_t recovered_grants_fenced_ = 0;
  bool started_ = false;
  bool consent_withdrawn_ = false;
  bool connect_scheduled_ = false;
};

}  // namespace icf::runtime
