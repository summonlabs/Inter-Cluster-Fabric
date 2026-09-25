// Inter-Cluster Fabric - authorization decisions and fence plans.
//
// A Decision answers the runtime's core question for one directed endpoint pair: is this
// connectivity authorized right now, under whose authority, and over which path. A FencePlan
// answers the complementary question: what must be withdrawn when a cluster changes.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "icf/core/hash.hpp"
#include "icf/model/terms.hpp"

namespace icf::model {

enum class ReasonCode : std::uint16_t {
  None = 0,
  EndpointsAreIdentical,
  SourceEndpointNotRegistered,
  TargetEndpointNotRegistered,
  SourceEndpointSuspended,
  TargetEndpointSuspended,
  SourceEndpointRefused,
  TargetEndpointRefused,
  ResourceUnknown,
  ResourceUnsupported,
  ResourceUnreachable,
  ResourcePartitioned,
  PolicyAllowed,
  PolicyRefused,
  PolicyMissingAllow,
  PolicyStaleGeneration,
  ClusterUnknown,
  ClusterSuspended,
  ClusterDraining,
  ClusterRetired,
  ClusterGenerationConflict,
  ClusterConsentWithdrawn,
  IncarnationMismatch,
  GenerationStale,
  PolicyGenerationStale,
  NoContract,
  ContractNotConsented,
  ContractRefused,
  ContractWithdrawn,
  ContractExpired,
  ContractFenced,
  ConsentMismatch,
  ConsentUnauthenticated,
  NoGrant,
  GrantNotCommitted,
  GrantNotAcknowledged,
  GrantIndeterminate,
  GrantFenced,
  GrantExpired,
  GrantTermMismatch,
  GrantNeedsRevalidation,
  GrantCapacityExceeded,
  PathAbsent,
  PathUnsupported,
  PathDown,
  PathDegraded,
  PathNotPermittedDegraded,
  LinkUnsupported,
  LinkDown,
  LinkDegraded,
  LinkUnknown,
  CapacityExhausted,
  EvidenceUnverified,
  EvidenceRecoveredFromStore,
  EvidenceIncomplete,
  AuthorityRequired,
  AuthoritySatisfied,
};

[[nodiscard]] const char* to_string(ReasonCode code) noexcept;

struct DecisionQuery {
  EndpointId source;
  EndpointId target;
  CapacityUnits requested_capacity;
  Timestamp at{};
  bool allow_degraded = false;
  // Optional expectations supplied by the caller. A mismatch produces STALE rather than being
  // ignored, so a caller can never silently observe a decision for the wrong generation.
  bool expect_source_generation = false;
  Generation source_generation;
  bool expect_target_generation = false;
  Generation target_generation;
};

struct Decision {
  Outcome outcome = Outcome::Indeterminate;
  std::vector<ReasonCode> reasons;
  ContractId contract;
  GrantId grant;
  std::array<AuthorityDomainId, kPartyCount> authorities;
  Term term;
  IncarnationId coordinator;
  Digest terms_digest;
  Digest view_digest;
  CapacityUnits capacity;
  std::vector<PathId> paths;
  std::vector<EdgeId> edges;
  bool degraded = false;
  Timestamp decided_at{};
  std::string detail;

  [[nodiscard]] bool authorized() const noexcept { return is_authorized(outcome); }
};

enum class FenceTrigger : std::uint8_t {
  Manual = 0,
  ClusterReincarnation = 1,
  ClusterWithdrawal = 2,
  PolicyGenerationChange = 3,
  CoordinatorReincarnation = 4,
  GrantRevocation = 5,
  LinkFailure = 6,
  GrantExpiry = 7,
};

[[nodiscard]] const char* to_string(FenceTrigger trigger) noexcept;

enum class FenceTarget : std::uint8_t {
  Grant = 0,
  Contract = 1,
  Reservation = 2,
};

[[nodiscard]] const char* to_string(FenceTarget target) noexcept;

struct FenceAction {
  FenceTarget target = FenceTarget::Grant;
  GrantId grant;
  ContractId contract;
  ReservationId reservation;
  ReasonCode reason = ReasonCode::None;
};

struct FencePlan {
  FenceTrigger trigger = FenceTrigger::Manual;
  ClusterId cluster;
  IncarnationId incarnation;
  IncarnationId previous_incarnation;
  Generation generation;
  Term term;
  Digest view_digest;
  std::vector<FenceAction> actions;
  std::string detail;
};

struct AccountingEntry {
  GrantId grant;
  ContractId contract;
  EndpointId endpoint;
  ClusterId cluster;
  CapacityUnits reserved;
  CapacityUnits released;
  bool closed = false;
};

struct CoordinatorStatus {
  AuthorityDomainId domain;
  IncarnationId incarnation;
  Term term;
  Timestamp started_at{};
  std::uint64_t uptime_nanos = 0;
  Digest view_digest;
  Revision revision;
  bool recovered_from_store = false;
  std::uint64_t recovered_records = 0;
  std::uint64_t truncations_recovered = 0;
  std::size_t clusters = 0;
  std::size_t endpoints = 0;
  std::size_t links = 0;
  std::size_t paths = 0;
  std::size_t contracts = 0;
  std::size_t grants = 0;
  std::size_t reservations = 0;
  std::size_t policies = 0;
  std::size_t audit = 0;
  std::size_t connected_agents = 0;
  std::uint64_t commits = 0;
  std::uint64_t fences = 0;
  std::uint64_t refusals = 0;
  std::uint64_t revalidations = 0;
  std::uint64_t rejected_replays = 0;
  std::uint64_t rejected_frames = 0;
  std::string store_path;
};

// ---- canonical encoding ---------------------------------------------------------
void encode_decision(const Decision& decision, ByteWriter& writer);
[[nodiscard]] Result<Decision> decode_decision(ByteReader& reader);
void encode_fence_plan(const FencePlan& plan, ByteWriter& writer);
[[nodiscard]] Result<FencePlan> decode_fence_plan(ByteReader& reader);
void encode_accounting(const AccountingEntry& entry, ByteWriter& writer);
[[nodiscard]] Result<AccountingEntry> decode_accounting(ByteReader& reader);
void encode_status(const CoordinatorStatus& status, ByteWriter& writer);
[[nodiscard]] Result<CoordinatorStatus> decode_status(ByteReader& reader);

}  // namespace icf::model
