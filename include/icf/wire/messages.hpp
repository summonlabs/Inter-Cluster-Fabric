// Inter-Cluster Fabric - protocol message schemas.
//
// Every message is a bounded, explicitly-versioned structure. Decoders validate every length,
// enumeration, and identity before the value is used, and reject trailing bytes: a message
// that carries fields this build does not know about is INVALID rather than silently trimmed.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "icf/model/decision.hpp"
#include "icf/model/registry.hpp"
#include "icf/wire/frame.hpp"

namespace icf::wire {

using model::AccountingEntry;
using model::AuditRecord;
using model::ClusterRecord;
using model::ClusterState;
using model::ConsentDecision;
using model::ContractRecord;
using model::ContractTerms;
using model::CoordinatorStatus;
using model::Decision;
using model::FencePlan;
using model::GrantRecord;
using model::GrantState;
using model::LinkRecord;
using model::LinkState;
using model::PathRecord;
using model::PolicyRule;
using model::ReservationRecord;

enum class PeerRole : std::uint8_t {
  Agent = 1,     // a cluster-side daemon that owns one cluster identity
  Observer = 2,  // an operator client: read-only plus explicit administrative actions
};

enum class QueryKind : std::uint8_t {
  Status = 1,
  ListClusters = 2,
  ShowCluster = 3,
  ListLinks = 4,
  ListPaths = 5,
  ListPolicies = 6,
  ListContracts = 7,
  ShowContract = 8,
  ListGrants = 9,
  ShowGrant = 10,
  ListReservations = 11,
  ListAudit = 12,
  Decide = 13,
  FencePlan = 14,
  Accounting = 15,
};

enum class AdminAction : std::uint8_t {
  UpsertCluster = 1,
  DeleteCluster = 2,
  SetClusterState = 3,
  UpsertLink = 4,
  SetLinkState = 5,
  DeleteLink = 6,
  UpsertPath = 7,
  DeletePath = 8,
  UpsertPolicy = 9,
  DeletePolicy = 10,
  WithdrawConsent = 11,
  RestoreConsent = 12,
  ResolveConflict = 13,
  AuthorizeContract = 14,
  IssueGrant = 15,
  RevalidateGrant = 16,
  FenceGrant = 17,
  ReloadStore = 18,
};

[[nodiscard]] const char* to_string(QueryKind kind) noexcept;
[[nodiscard]] const char* to_string(AdminAction action) noexcept;
[[nodiscard]] bool query_kind_from_string(std::string_view text, QueryKind& out) noexcept;
[[nodiscard]] bool admin_action_from_string(std::string_view text, AdminAction& out) noexcept;

inline constexpr std::uint32_t kCapabilityFencing = 0x00000001u;
inline constexpr std::uint32_t kCapabilityRevalidation = 0x00000002u;
inline constexpr std::uint32_t kCapabilityStatusReport = 0x00000004u;
inline constexpr std::uint32_t kCapabilityTwoSidedConsent = 0x00000008u;
inline constexpr std::uint32_t kCapabilityAll =
    kCapabilityFencing | kCapabilityRevalidation | kCapabilityStatusReport | kCapabilityTwoSidedConsent;

struct HelloMessage {
  PeerRole role = PeerRole::Agent;
  ClusterId cluster;
  AuthorityDomainId domain;
  IncarnationId incarnation;
  Generation generation;
  PolicyGeneration policy_generation;
  Term agent_term;
  std::uint16_t protocol_min = limits::kProtocolVersionMin;
  std::uint16_t protocol_max = limits::kProtocolVersionMax;
  std::uint32_t capabilities = 0;
  Digest content_digest;
  Timestamp started_at{};
};

struct HelloAckMessage {
  SessionToken session;
  IncarnationId coordinator;
  Term coordinator_term;
  Outcome outcome = Outcome::Internal;
  std::uint16_t negotiated_version = 0;
  Digest view_digest;
  std::vector<GrantId> revalidate;
  std::string detail;
};

struct RefuseMessage {
  Outcome outcome = Outcome::Internal;
  std::string detail;
};

struct PingMessage {
  Sequence sequence;
  Timestamp sent_at{};
};

struct PongMessage {
  Sequence sequence;
};

struct ReportClusterMessage {
  SessionToken session;
  ClusterRecord cluster;
};

struct ReportAckMessage {
  SessionToken session;
  Outcome outcome = Outcome::Internal;
  Revision revision;
  Digest view_digest;
  std::string detail;
};

struct ProposeContractMessage {
  SessionToken session;
  ContractId contract;
  ContractTerms terms;
  AttemptId attempt;
};

struct ContractConsentMessage {
  SessionToken session;
  ContractId contract;
  Digest terms_digest;
  ConsentDecision decision = ConsentDecision::Refused;
  EndpointId endpoint;
  IncarnationId incarnation;
  Generation generation;
  PolicyGeneration policy_generation;
  Term agent_term;
  std::string reason;
};

struct PrepareGrantMessage {
  SessionToken session;
  GrantRecord grant;
};

struct GrantPreparedMessage {
  SessionToken session;
  GrantId grant;
  AttemptId attempt;
  bool accepted = false;
  Term agent_term;
  Digest enforcement_digest;
  std::string detail;
};

struct CommitGrantMessage {
  SessionToken session;
  GrantId grant;
  AttemptId attempt;
};

struct GrantCommittedMessage {
  SessionToken session;
  GrantId grant;
  AttemptId attempt;
  bool installed = false;
  Term agent_term;
  Digest enforcement_digest;
  std::string detail;
};

struct AbortGrantMessage {
  SessionToken session;
  GrantId grant;
  AttemptId attempt;
  std::string reason;
};

struct GrantAbortedMessage {
  SessionToken session;
  GrantId grant;
  AttemptId attempt;
  std::string reason;
};

struct FenceMessage {
  SessionToken session;
  Term coordinator_term;
  std::vector<GrantId> grants;
  std::string reason;
};

struct FenceResult {
  GrantId grant;
  Outcome outcome = Outcome::Internal;
};

struct FenceAckMessage {
  SessionToken session;
  std::vector<FenceResult> results;
};

struct WithdrawMessage {
  SessionToken session;
  ClusterId cluster;
  IncarnationId incarnation;
  Generation generation;
  std::string reason;
};

struct WithdrawAckMessage {
  SessionToken session;
  Outcome outcome = Outcome::Internal;
  std::uint64_t fenced_grants = 0;
  std::string detail;
};

struct StatusRequestMessage {
  SessionToken session;
  Uuid request;
};

struct GrantStatusEntry {
  GrantId grant;
  AttemptId attempt;
  GrantState state = GrantState::Aborted;
  Term agent_term;
  Digest enforcement_digest;
};

struct StatusReportMessage {
  SessionToken session;
  Uuid request;
  ClusterId cluster;
  IncarnationId incarnation;
  Generation generation;
  PolicyGeneration policy_generation;
  Term agent_term;
  std::vector<GrantStatusEntry> grants;
};

struct QueryMessage {
  Uuid request;
  QueryKind kind = QueryKind::Status;
  ClusterId cluster;
  ClusterId cluster_b;
  EndpointId endpoint;
  EndpointId endpoint_b;
  ContractId contract;
  GrantId grant;
  EdgeId edge;
  std::string policy_id;
  CapacityUnits capacity;
  bool allow_degraded = false;
  std::uint32_t limit = 0;
  bool expect_source_generation = false;
  Generation source_generation;
  bool expect_target_generation = false;
  Generation target_generation;
  Timestamp at{};
};

struct QueryResultMessage {
  Uuid request;
  QueryKind kind = QueryKind::Status;
  Outcome outcome = Outcome::Internal;
  std::string detail;
  std::vector<ClusterRecord> clusters;
  std::vector<LinkRecord> links;
  std::vector<PathRecord> paths;
  std::vector<PolicyRule> policies;
  std::vector<ContractRecord> contracts;
  std::vector<GrantRecord> grants;
  std::vector<ReservationRecord> reservations;
  std::vector<AuditRecord> audit;
  std::vector<AccountingEntry> accounting;
  std::optional<Decision> decision;
  std::optional<FencePlan> fence_plan;
  std::optional<CoordinatorStatus> status;
};

struct AdminMessage {
  Uuid request;
  AdminAction action = AdminAction::UpsertCluster;
  std::optional<ClusterRecord> cluster;
  std::optional<LinkRecord> link;
  std::optional<PathRecord> path;
  std::optional<PolicyRule> policy;
  ClusterId cluster_id;
  ClusterId cluster_b;
  EndpointId endpoint;
  EndpointId endpoint_b;
  ContractId contract;
  GrantId grant;
  EdgeId edge;
  std::string policy_id;
  Generation generation;
  ClusterState cluster_state = ClusterState::Unknown;
  LinkState link_state = LinkState::Unknown;
  CapacityUnits capacity;
  Duration lease_duration;
  std::string reason;
};

struct AdminResultMessage {
  Uuid request;
  Outcome outcome = Outcome::Internal;
  std::string detail;
  Digest view_digest;
  Revision revision;
  // The artifact the action created or addressed. A nil identity means "not applicable", which
  // is distinct from "created with an unknown identity".
  ContractId contract;
  GrantId grant;
};

struct ErrorMessage {
  Uuid request;
  Outcome outcome = Outcome::Internal;
  std::string detail;
};

// ---- canonical encodings --------------------------------------------------------
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const HelloMessage& message);
[[nodiscard]] Result<HelloMessage> decode_hello(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const HelloAckMessage& message);
[[nodiscard]] Result<HelloAckMessage> decode_hello_ack(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const RefuseMessage& message);
[[nodiscard]] Result<RefuseMessage> decode_refuse(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const PingMessage& message);
[[nodiscard]] Result<PingMessage> decode_ping(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const PongMessage& message);
[[nodiscard]] Result<PongMessage> decode_pong(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const ReportClusterMessage& message);
[[nodiscard]] Result<ReportClusterMessage> decode_report_cluster(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const ReportAckMessage& message);
[[nodiscard]] Result<ReportAckMessage> decode_report_ack(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const ProposeContractMessage& message);
[[nodiscard]] Result<ProposeContractMessage> decode_propose_contract(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const ContractConsentMessage& message);
[[nodiscard]] Result<ContractConsentMessage> decode_contract_consent(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const PrepareGrantMessage& message);
[[nodiscard]] Result<PrepareGrantMessage> decode_prepare_grant(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const GrantPreparedMessage& message);
[[nodiscard]] Result<GrantPreparedMessage> decode_grant_prepared(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const CommitGrantMessage& message);
[[nodiscard]] Result<CommitGrantMessage> decode_commit_grant(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const GrantCommittedMessage& message);
[[nodiscard]] Result<GrantCommittedMessage> decode_grant_committed(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const AbortGrantMessage& message);
[[nodiscard]] Result<AbortGrantMessage> decode_abort_grant(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const GrantAbortedMessage& message);
[[nodiscard]] Result<GrantAbortedMessage> decode_grant_aborted(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const FenceMessage& message);
[[nodiscard]] Result<FenceMessage> decode_fence(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const FenceAckMessage& message);
[[nodiscard]] Result<FenceAckMessage> decode_fence_ack(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const WithdrawMessage& message);
[[nodiscard]] Result<WithdrawMessage> decode_withdraw(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const WithdrawAckMessage& message);
[[nodiscard]] Result<WithdrawAckMessage> decode_withdraw_ack(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const StatusRequestMessage& message);
[[nodiscard]] Result<StatusRequestMessage> decode_status_request(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const StatusReportMessage& message);
[[nodiscard]] Result<StatusReportMessage> decode_status_report(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const QueryMessage& message);
[[nodiscard]] Result<QueryMessage> decode_query(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const QueryResultMessage& message);
[[nodiscard]] Result<QueryResultMessage> decode_query_result(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const AdminMessage& message);
[[nodiscard]] Result<AdminMessage> decode_admin(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const AdminResultMessage& message);
[[nodiscard]] Result<AdminResultMessage> decode_admin_result(ByteReader& reader);
[[nodiscard]] Result<std::vector<std::byte>> encode_message(const ErrorMessage& message);
[[nodiscard]] Result<ErrorMessage> decode_error(ByteReader& reader);

}  // namespace icf::wire
