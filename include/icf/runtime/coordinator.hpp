// Inter-Cluster Fabric - the authority coordinator.
//
// The coordinator owns the authoritative view: cluster incarnations and generations, endpoint
// scopes, links and paths, policy generations, two-sided contracts, grants, reservations, and
// the authority term. It is the only component that issues a grant, and a grant is only usable
// when both cluster-side agents have acknowledged the exact same attempt.
//
// Lifecycle: create() -> start() -> serve() -> stop(). Every durable write happens before the
// effect it authorizes is observable.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "icf/core/config.hpp"
#include "icf/core/rng.hpp"
#include "icf/core/time.hpp"
#include "icf/net/reactor.hpp"
#include "icf/runtime/engine.hpp"
#include "icf/store/durable_store.hpp"
#include "icf/wire/messages.hpp"

namespace icf::runtime {

// Records the coordinator's view of one connected peer.
struct PeerSession {
  wire::PeerRole role = wire::PeerRole::Observer;
  ClusterId cluster;
  AuthorityDomainId domain;
  SessionToken token;
  IncarnationId incarnation;
  Generation generation;
  PolicyGeneration policy_generation;
  Term agent_term;
  bool signing = false;
  bool hello_complete = false;
  Timestamp connected_at{};
  std::uint64_t connection_id = 0;
  std::uint64_t messages = 0;
};

class Coordinator {
 public:
  struct Config {
    std::string state_directory;
    std::string listen_address = "127.0.0.1";
    std::uint16_t listen_port = 0;
    AuthorityDomainId domain;
    bool durable = true;
    bool allow_agent_registration = true;
    // Shared channel keys per authority domain. When a domain has a key, every frame from that
    // domain must carry a valid HMAC-SHA256 tag.
    std::map<std::string, std::string> domain_keys;
    Duration agent_idle_deadline = Duration::from_millis(30000);
    Duration default_lease = Duration::from_seconds(120);
    Duration ping_interval = Duration::from_seconds(5);
    Duration grant_flow_deadline = Duration::from_seconds(10);
    std::uint64_t compact_bytes = 8ull << 20;
    std::uint64_t compact_records = 16384;
    std::size_t max_connections = limits::kMaxConnections;
    std::string readiness_file;
  };

  [[nodiscard]] static Result<std::unique_ptr<Coordinator>> create(Config config, const Clock& clock);
  ~Coordinator();
  Coordinator(const Coordinator&) = delete;
  Coordinator& operator=(const Coordinator&) = delete;

  // Loads the store, establishes a new authority term, binds the listener, and installs the
  // periodic timers. Returns a negative status when the persisted state cannot be trusted.
  [[nodiscard]] Status start();
  // Runs the event loop until stop() is called.
  [[nodiscard]] Status serve();
  void stop() noexcept;

  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] const model::Registry& registry() const noexcept { return registry_; }
  [[nodiscard]] Term term() const noexcept { return term_; }
  [[nodiscard]] IncarnationId incarnation() const noexcept { return incarnation_; }
  [[nodiscard]] model::CoordinatorStatus status() const;
  [[nodiscard]] const store::DurableStore::Recovery& recovery() const noexcept { return recovery_; }

  // Message entry point. The event loop calls this with a real connection id; tests call it with
  // the virtual connection id 0 to drive the same state machine without sockets.
  [[nodiscard]] Status handle_message(std::uint64_t connection_id, const wire::Frame& frame);
  void handle_disconnect(std::uint64_t connection_id, const Status& reason);
  [[nodiscard]] net::Connection* connection_for(std::uint64_t id);

  [[nodiscard]] Status handle_query(const wire::QueryMessage& query, wire::QueryResultMessage& result) const;
  [[nodiscard]] Status handle_admin(const wire::AdminMessage& request, wire::AdminResultMessage& result);

  // Deterministic housekeeping, exposed so tests can drive time forward without sockets.
  void tick();
  void expire_grants();
  void retry_pending_flows();

  [[nodiscard]] const std::map<std::uint64_t, PeerSession>& sessions() const noexcept { return sessions_; }

 private:
  Coordinator(Config config, const Clock& clock);

  struct SendTarget {
    bool connected = false;
    std::uint64_t connection_id = 0;
    SessionToken token;
  };

  struct PendingGrant {
    GrantId grant;
    ContractId contract;
    std::array<bool, model::kPartyCount> prepared{false, false};
    std::array<SendTarget, model::kPartyCount> targets;
    Timestamp deadline{};
    std::uint32_t attempts = 0;
  };

  [[nodiscard]] Status load_state();
  [[nodiscard]] Status begin_incarnation();
  [[nodiscard]] Status append_mutation(const store::Mutation& mutation);
  [[nodiscard]] Status append_audit(std::string actor, std::string action, std::string subject, Outcome outcome,
                                    std::string detail);
  [[nodiscard]] Status listen();
  [[nodiscard]] Status install_timers();

  [[nodiscard]] Status on_hello(std::uint64_t connection_id, const wire::Frame& frame);
  [[nodiscard]] Status on_report_cluster(std::uint64_t connection_id, const wire::Frame& frame);
  [[nodiscard]] Status on_contract_consent(std::uint64_t connection_id, const wire::Frame& frame);
  [[nodiscard]] Status on_grant_prepared(std::uint64_t connection_id, const wire::Frame& frame);
  [[nodiscard]] Status on_grant_committed(std::uint64_t connection_id, const wire::Frame& frame);
  [[nodiscard]] Status on_grant_aborted(std::uint64_t connection_id, const wire::Frame& frame);
  [[nodiscard]] Status on_fence_ack(std::uint64_t connection_id, const wire::Frame& frame);
  [[nodiscard]] Status on_withdraw(std::uint64_t connection_id, const wire::Frame& frame);
  [[nodiscard]] Status on_status_report(std::uint64_t connection_id, const wire::Frame& frame);
  [[nodiscard]] Status on_query(std::uint64_t connection_id, const wire::Frame& frame);
  [[nodiscard]] Status on_admin(std::uint64_t connection_id, const wire::Frame& frame);
  [[nodiscard]] Status on_ping(std::uint64_t connection_id, const wire::Frame& frame);

  [[nodiscard]] Status send_refuse(std::uint64_t connection_id, Outcome outcome, const std::string& detail);
  [[nodiscard]] Status send_error(std::uint64_t connection_id, const Uuid& request, Outcome outcome,
                                  const std::string& detail);
  [[nodiscard]] PeerSession* session_for(std::uint64_t connection_id);
  [[nodiscard]] const PeerSession* session_for(std::uint64_t connection_id) const;
  [[nodiscard]] Status require_session(std::uint64_t connection_id, const SessionToken& token, PeerSession*& session);
  [[nodiscard]] SendTarget target_for(const ClusterId& cluster) const;

  [[nodiscard]] Status apply_contract_proposal(const wire::AdminMessage& request, wire::AdminResultMessage& result);
  [[nodiscard]] Status apply_grant_issue(const wire::AdminMessage& request, wire::AdminResultMessage& result);
  [[nodiscard]] Status apply_grant_revalidation(const wire::AdminMessage& request, wire::AdminResultMessage& result);
  [[nodiscard]] Status apply_consent_change(const wire::AdminMessage& request, wire::AdminResultMessage& result,
                                            bool withdraw);
  [[nodiscard]] Status apply_conflict_resolution(const wire::AdminMessage& request, wire::AdminResultMessage& result);
  [[nodiscard]] Status propose_contract_to_agents(const model::ContractRecord& contract);
  [[nodiscard]] Status prepare_grant(model::GrantRecord& grant);
  [[nodiscard]] Status commit_grant(const GrantId& grant);
  [[nodiscard]] Status finalise_grant(const GrantId& grant, Timestamp at);
  [[nodiscard]] Status abort_grant(const GrantId& grant, const std::string& reason);
  [[nodiscard]] Status fence_plan_apply(const model::FencePlan& plan, const std::string& actor);
  [[nodiscard]] Status fence_cluster(const ClusterId& cluster, model::FenceTrigger trigger,
                                     const IncarnationId& new_incarnation, const IncarnationId& previous_incarnation,
                                     const Generation& generation);
  [[nodiscard]] Status reserve_capacity(const model::GrantRecord& grant, Timestamp at);
  [[nodiscard]] Status compact_if_needed();
  [[nodiscard]] Status enqueue(std::uint64_t connection_id, wire::MessageType type, ByteWriter& writer,
                               bool sign_for_peer);
  [[nodiscard]] std::vector<std::byte> channel_key_for(const AuthorityDomainId& domain) const;

  Config config_;
  const Clock* clock_;
  store::DurableStore store_;
  store::DurableStore::Recovery recovery_;
  model::Registry registry_;
  Term term_;
  IncarnationId incarnation_;
  IncarnationId previous_incarnation_;
  Timestamp started_at_{};
  net::EventLoop loop_;
  net::TcpListener listener_;
  std::uint16_t port_ = 0;
  std::map<std::uint64_t, PeerSession> sessions_;
  std::map<GrantId, PendingGrant> pending_;
  Rng rng_;
  std::uint64_t commits_ = 0;
  std::uint64_t fences_ = 0;
  std::uint64_t refusals_ = 0;
  std::uint64_t revalidations_ = 0;
  std::uint64_t rejected_replays_ = 0;
  std::uint64_t rejected_frames_ = 0;
  std::uint64_t pongs_received_ = 0;
  std::uint64_t errors_received_ = 0;
  std::uint64_t next_tick_ = 0;
  bool started_ = false;
};

}  // namespace icf::runtime
