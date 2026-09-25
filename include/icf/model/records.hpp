// Inter-Cluster Fabric - authoritative records.
//
// These are the values the coordinator owns: cluster incarnations and generations, endpoint
// scopes, inter-cluster links and paths, capacity, policy generations, two-sided contracts,
// grants, reservations, and the evidence trail behind each of them.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "icf/core/hash.hpp"
#include "icf/core/ids.hpp"
#include "icf/core/time.hpp"
#include "icf/model/types.hpp"

namespace icf::model {

inline constexpr std::size_t kPartyCount = 2;

struct EndpointRecord {
  EndpointId id;
  ClusterId cluster;
  ScopeName scope;
  CapacityUnits capacity;
  CapacityUnits reserved;
  PolicyGeneration policy_generation;
  EndpointState state = EndpointState::Unknown;
  bool inter_cluster_allowed = false;
  bool permits_degraded = false;
  Provenance provenance;
};

struct ClusterRecord {
  ClusterId id;
  AuthorityDomainId domain;
  IncarnationId incarnation;
  Generation generation;
  PolicyGeneration policy_generation;
  ClusterState state = ClusterState::Unknown;
  bool consent_withdrawn = false;   // administrative withdrawal: fences every dependent grant
  Timestamp last_seen{};
  std::vector<EndpointRecord> endpoints;  // sorted by endpoint id
  Digest content_digest{};          // digest of the agent-reported content at `generation`
  // Set when two updates claim the same generation with different content. The coordinator
  // refuses to authorize the cluster until an operator resolves it explicitly.
  bool generation_conflict = false;
  std::optional<Generation> conflicting_generation;
  Revision revision{};
  Provenance provenance;
  std::uint64_t incarnation_changes = 0;  // how many reincarnations were observed
};

struct LinkRecord {
  EdgeId id;
  EndpointId a;
  EndpointId b;
  LinkKind kind = LinkKind::Unknown;
  LinkState state = LinkState::Unknown;
  CapacityUnits capacity;
  CapacityUnits reserved;
  std::uint32_t latency_micros = 0;
  Revision revision{};
  Provenance provenance;
};

struct PathRecord {
  PathId id;
  EndpointId a;
  EndpointId b;
  std::vector<EdgeId> hops;  // ordered edges (each direction-agnostic)
  CapacityUnits bottleneck;
  PathState state = PathState::Unknown;
  Revision revision{};
  Provenance provenance;
  // The physical technology behind the path is never asserted: paths are derived from the
  // declared edges, and an unsupported edge makes the whole path unsupported.
  bool contains_unsupported_edge = false;
};

struct ConsentRecord {
  ClusterId cluster;
  EndpointId endpoint;
  IncarnationId incarnation;
  Generation generation;
  PolicyGeneration policy_generation;
  Term agent_term;  // the accepting agent's own fencing term
  Digest terms_digest;
  ConsentDecision decision = ConsentDecision::Refused;
  Timestamp decided_at{};
  SessionToken session;
  TransportAuthenticity authenticity = TransportAuthenticity::None;
  std::string reason;  // bounded operator/agent supplied explanation
};

struct PartyRef {
  ClusterId cluster;
  EndpointId endpoint;
  AuthorityDomainId domain;
};

struct ContractRecord {
  ContractId id;
  std::array<PartyRef, kPartyCount> parties;
  CapacityUnits capacity;
  Duration lease_duration;
  Digest terms_digest{};
  ContractState state = ContractState::Proposed;
  std::array<std::optional<ConsentRecord>, kPartyCount> consents;
  Timestamp created_at{};
  Timestamp updated_at{};
  Revision revision{};
  Provenance provenance;

  [[nodiscard]] int side_of(const ClusterId& cluster) const noexcept;
  [[nodiscard]] bool both_consented() const noexcept;
};

struct GrantRecord {
  GrantId id;
  ContractId contract;
  Digest terms_digest;
  Term coordinator_term;             // coordinator fencing term at issue time
  IncarnationId coordinator;         // coordinator incarnation that issued the grant
  AttemptId attempt;
  std::array<IncarnationId, kPartyCount> incarnations;
  std::array<Generation, kPartyCount> generations;
  std::array<PolicyGeneration, kPartyCount> policies;
  CapacityUnits capacity;
  Timestamp issued_at{};
  Timestamp valid_until{};
  GrantState state = GrantState::Preparing;
  std::array<bool, kPartyCount> acknowledged{false, false};
  std::array<Digest, kPartyCount> enforcement_digest;
  std::uint64_t revalidate_attempts = 0;
  std::string note;  // bounded operator-visible detail about the current state
  Revision revision{};
  Provenance provenance;

  // Usable only when both sides acknowledged the exact same attempt under the same terms.
  [[nodiscard]] bool both_acknowledged() const noexcept { return acknowledged[0] && acknowledged[1]; }
  [[nodiscard]] bool usable_state() const noexcept {
    return state == GrantState::Committed || state == GrantState::Active;
  }
};

struct ReservationRecord {
  ReservationId id;
  GrantId grant;
  EndpointId endpoint;
  ClusterId cluster;
  CapacityUnits amount;
  bool released = false;
  Timestamp created_at{};
  Timestamp released_at{};
  Revision revision{};
  Provenance provenance;
};

struct AuditRecord {
  Sequence sequence;
  Timestamp at{};
  std::string actor;    // bounded: component or operator identity
  std::string action;   // bounded verb
  std::string subject;  // bounded: the record the action touched
  Outcome outcome = Outcome::Ok;
  std::string detail;   // bounded
};

struct PolicyRule {
  std::string id;  // bounded name, unique within the owning domain
  AuthorityDomainId owner;
  ClusterId cluster_a;
  ClusterId cluster_b;
  EndpointId endpoint_a;
  EndpointId endpoint_b;
  PolicyGeneration generation;
  bool allow = false;          // deny-by-default: authorization needs an explicit allow
  bool allow_degraded = false; // whether a degraded path may be authorized under this rule
  CapacityUnits max_capacity;  // 0 means "no additional limit"
  Revision revision{};
  Provenance provenance;

  // An empty match field is a wildcard.
  [[nodiscard]] bool matches(const ClusterId& a, const ClusterId& b, const EndpointId& ea,
                             const EndpointId& eb) const noexcept;
};

}  // namespace icf::model
