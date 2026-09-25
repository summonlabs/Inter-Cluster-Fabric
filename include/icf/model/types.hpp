// Inter-Cluster Fabric - model enumerations and evidence provenance.
//
// Every state value that participates in an authorization decision is an explicit enumeration.
// There is no "assume healthy" default: records start in Unknown/Unverified states and stay
// there until a named authority supplies verified evidence.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "icf/core/hash.hpp"
#include "icf/core/ids.hpp"
#include "icf/core/time.hpp"

namespace icf::model {

enum class ClusterState : std::uint8_t {
  Unknown = 0,     // no verified observation from this cluster
  Active = 1,      // the cluster reports itself able to carry cross-cluster connectivity
  Suspended = 2,   // administratively suspended
  Draining = 3,    // accepting no new grants, existing grants wind down
  Retired = 4,     // identity closed; grants must be fenced
};

enum class EndpointState : std::uint8_t {
  Unknown = 0,
  Active = 1,
  Suspended = 2,
  Draining = 3,
  Retired = 4,
};

// Link kinds distinguish what is actually proven. LoopbackTcp is a real framed transport over
// a real socket; OpticalInterconnect is declared but UNSUPPORTED because this runtime owns no
// optical hardware control path and never pretends to.
enum class LinkKind : std::uint16_t {
  Unknown = 0,
  LoopbackTcp = 1,         // REAL: framed transport over a real TCP socket
  SyntheticModel = 2,      // SYNTHETIC: operator-declared topology with no transport checked
  OpticalInterconnect = 3, // UNSUPPORTED: no hardware control path exists in this runtime
};

enum class LinkState : std::uint8_t {
  Unknown = 0,
  Up = 1,
  Degraded = 2,     // carrying traffic, but with reduced capacity or elevated loss
  Down = 3,
  Unsupported = 4,  // the runtime cannot drive or observe this link kind
};

enum class PathState : std::uint8_t {
  Unknown = 0,
  Up = 1,
  Degraded = 2,
  Down = 3,
};

enum class ContractState : std::uint8_t {
  Proposed = 0,        // the coordinator holds terms, no consent yet
  AwaitingConsent = 1, // at least one side has been asked
  Consented = 2,       // both sides accepted identical terms; no grant issued yet
  Active = 3,          // a grant is committed and not fenced
  Refused = 4,         // one side explicitly refused (REFUSED is distinct from UNAUTHORIZED)
  Withdrawn = 5,       // a side withdrew consent after consenting
  Expired = 6,
  Fenced = 7,          // superseded by a new incarnation/generation/term
};

enum class GrantState : std::uint8_t {
  Preparing = 0,      // coordinator-intent only; unusable
  Prepared = 1,       // one or both sides recorded the intent; unusable
  Committed = 2,      // both sides acknowledged; usable while the terms stay current
  Active = 3,         // enforcement installed on both sides
  Indeterminate = 4,  // commit/ack ambiguity: never usable, must be revalidated
  Aborted = 5,
  Fenced = 6,
  Expired = 7,
  Withdrawn = 8,
};

enum class ConsentDecision : std::uint8_t {
  Accepted = 0,
  Refused = 1,
};

// Where a piece of evidence came from. RecoveredFromStore marks dynamic evidence that
// survived a restart: it is historical and never silently fresh.
enum class EvidenceSource : std::uint8_t {
  Unspecified = 0,
  AdminConfigured = 1,
  AgentReported = 2,
  DerivedFromTopology = 3,
  RecoveredFromStore = 4,
  Synthetic = 5,
};

enum class VerificationState : std::uint8_t {
  Unverified = 0,
  Verified = 1,
  Failed = 2,
  NotApplicable = 3,
  Unsupported = 4,
};

enum class TransportAuthenticity : std::uint8_t {
  None = 0,        // no channel key configured: the peer is unauthenticated
  SharedKeyMac = 1,  // every frame carried a valid HMAC-SHA256 under the domain key
};

[[nodiscard]] const char* to_string(ClusterState value) noexcept;
[[nodiscard]] const char* to_string(EndpointState value) noexcept;
[[nodiscard]] const char* to_string(LinkKind value) noexcept;
[[nodiscard]] const char* to_string(LinkState value) noexcept;
[[nodiscard]] const char* to_string(PathState value) noexcept;
[[nodiscard]] const char* to_string(ContractState value) noexcept;
[[nodiscard]] const char* to_string(GrantState value) noexcept;
[[nodiscard]] const char* to_string(ConsentDecision value) noexcept;
[[nodiscard]] const char* to_string(EvidenceSource value) noexcept;
[[nodiscard]] const char* to_string(VerificationState value) noexcept;
[[nodiscard]] const char* to_string(TransportAuthenticity value) noexcept;

[[nodiscard]] bool cluster_state_from_string(std::string_view text, ClusterState& out) noexcept;
[[nodiscard]] bool endpoint_state_from_string(std::string_view text, EndpointState& out) noexcept;
[[nodiscard]] bool link_kind_from_string(std::string_view text, LinkKind& out) noexcept;
[[nodiscard]] bool link_state_from_string(std::string_view text, LinkState& out) noexcept;

struct Provenance {
  EvidenceSource source = EvidenceSource::Unspecified;
  VerificationState verification = VerificationState::Unverified;
  Timestamp observed_at{};
  Revision revision{};
  SessionToken session{};
  Digest evidence_digest{};

  // True when this evidence may be used for a fresh authorization decision. Evidence read
  // back from disk is historical and must be revalidated with the authority that produced it.
  [[nodiscard]] bool usable() const noexcept {
    return verification == VerificationState::Verified && source != EvidenceSource::RecoveredFromStore &&
           source != EvidenceSource::Unspecified;
  }
};

// A link that the runtime cannot drive is reported as unsupported rather than as down.
[[nodiscard]] bool link_kind_supported(LinkKind kind) noexcept;
[[nodiscard]] const char* link_kind_support_note(LinkKind kind) noexcept;

}  // namespace icf::model
