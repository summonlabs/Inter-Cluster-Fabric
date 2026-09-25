#include "icf/model/records.hpp"

#include <string_view>

namespace icf::model {
namespace {

template <class Enum, std::size_t N>
bool parse_enum(const std::array<std::pair<Enum, const char*>, N>& table, std::string_view text, Enum& out) noexcept {
  for (const auto& entry : table) {
    if (text == entry.second) {
      out = entry.first;
      return true;
    }
  }
  return false;
}

}  // namespace

const char* to_string(ClusterState value) noexcept {
  switch (value) {
    case ClusterState::Unknown:
      return "UNKNOWN";
    case ClusterState::Active:
      return "ACTIVE";
    case ClusterState::Suspended:
      return "SUSPENDED";
    case ClusterState::Draining:
      return "DRAINING";
    case ClusterState::Retired:
      return "RETIRED";
  }
  return "UNKNOWN";
}

const char* to_string(EndpointState value) noexcept {
  switch (value) {
    case EndpointState::Unknown:
      return "UNKNOWN";
    case EndpointState::Active:
      return "ACTIVE";
    case EndpointState::Suspended:
      return "SUSPENDED";
    case EndpointState::Draining:
      return "DRAINING";
    case EndpointState::Retired:
      return "RETIRED";
  }
  return "UNKNOWN";
}

const char* to_string(LinkKind value) noexcept {
  switch (value) {
    case LinkKind::Unknown:
      return "UNKNOWN";
    case LinkKind::LoopbackTcp:
      return "LOOPBACK_TCP";
    case LinkKind::SyntheticModel:
      return "SYNTHETIC_MODEL";
    case LinkKind::OpticalInterconnect:
      return "OPTICAL_INTERCONNECT";
  }
  return "UNKNOWN";
}

const char* to_string(LinkState value) noexcept {
  switch (value) {
    case LinkState::Unknown:
      return "UNKNOWN";
    case LinkState::Up:
      return "UP";
    case LinkState::Degraded:
      return "DEGRADED";
    case LinkState::Down:
      return "DOWN";
    case LinkState::Unsupported:
      return "UNSUPPORTED";
  }
  return "UNKNOWN";
}

const char* to_string(PathState value) noexcept {
  switch (value) {
    case PathState::Unknown:
      return "UNKNOWN";
    case PathState::Up:
      return "UP";
    case PathState::Degraded:
      return "DEGRADED";
    case PathState::Down:
      return "DOWN";
  }
  return "UNKNOWN";
}

const char* to_string(ContractState value) noexcept {
  switch (value) {
    case ContractState::Proposed:
      return "PROPOSED";
    case ContractState::AwaitingConsent:
      return "AWAITING_CONSENT";
    case ContractState::Consented:
      return "CONSENTED";
    case ContractState::Active:
      return "ACTIVE";
    case ContractState::Refused:
      return "REFUSED";
    case ContractState::Withdrawn:
      return "WITHDRAWN";
    case ContractState::Expired:
      return "EXPIRED";
    case ContractState::Fenced:
      return "FENCED";
  }
  return "PROPOSED";
}

const char* to_string(GrantState value) noexcept {
  switch (value) {
    case GrantState::Preparing:
      return "PREPARING";
    case GrantState::Prepared:
      return "PREPARED";
    case GrantState::Committed:
      return "COMMITTED";
    case GrantState::Active:
      return "ACTIVE";
    case GrantState::Indeterminate:
      return "INDETERMINATE";
    case GrantState::Aborted:
      return "ABORTED";
    case GrantState::Fenced:
      return "FENCED";
    case GrantState::Expired:
      return "EXPIRED";
    case GrantState::Withdrawn:
      return "WITHDRAWN";
  }
  return "PREPARING";
}

const char* to_string(ConsentDecision value) noexcept {
  switch (value) {
    case ConsentDecision::Accepted:
      return "ACCEPTED";
    case ConsentDecision::Refused:
      return "REFUSED";
  }
  return "REFUSED";
}

const char* to_string(EvidenceSource value) noexcept {
  switch (value) {
    case EvidenceSource::Unspecified:
      return "UNSPECIFIED";
    case EvidenceSource::AdminConfigured:
      return "ADMIN_CONFIGURED";
    case EvidenceSource::AgentReported:
      return "AGENT_REPORTED";
    case EvidenceSource::DerivedFromTopology:
      return "DERIVED_FROM_TOPOLOGY";
    case EvidenceSource::RecoveredFromStore:
      return "RECOVERED_FROM_STORE";
    case EvidenceSource::Synthetic:
      return "SYNTHETIC";
  }
  return "UNSPECIFIED";
}

const char* to_string(VerificationState value) noexcept {
  switch (value) {
    case VerificationState::Unverified:
      return "UNVERIFIED";
    case VerificationState::Verified:
      return "VERIFIED";
    case VerificationState::Failed:
      return "FAILED";
    case VerificationState::NotApplicable:
      return "NOT_APPLICABLE";
    case VerificationState::Unsupported:
      return "UNSUPPORTED";
  }
  return "UNVERIFIED";
}

const char* to_string(TransportAuthenticity value) noexcept {
  switch (value) {
    case TransportAuthenticity::None:
      return "NONE";
    case TransportAuthenticity::SharedKeyMac:
      return "SHARED_KEY_MAC";
  }
  return "NONE";
}

bool cluster_state_from_string(std::string_view text, ClusterState& out) noexcept {
  static const std::array<std::pair<ClusterState, const char*>, 5> kTable{{
      {ClusterState::Unknown, "UNKNOWN"},
      {ClusterState::Active, "ACTIVE"},
      {ClusterState::Suspended, "SUSPENDED"},
      {ClusterState::Draining, "DRAINING"},
      {ClusterState::Retired, "RETIRED"},
  }};
  return parse_enum(kTable, text, out);
}

bool endpoint_state_from_string(std::string_view text, EndpointState& out) noexcept {
  static const std::array<std::pair<EndpointState, const char*>, 5> kTable{{
      {EndpointState::Unknown, "UNKNOWN"},
      {EndpointState::Active, "ACTIVE"},
      {EndpointState::Suspended, "SUSPENDED"},
      {EndpointState::Draining, "DRAINING"},
      {EndpointState::Retired, "RETIRED"},
  }};
  return parse_enum(kTable, text, out);
}

bool link_kind_from_string(std::string_view text, LinkKind& out) noexcept {
  static const std::array<std::pair<LinkKind, const char*>, 4> kTable{{
      {LinkKind::Unknown, "UNKNOWN"},
      {LinkKind::LoopbackTcp, "LOOPBACK_TCP"},
      {LinkKind::SyntheticModel, "SYNTHETIC_MODEL"},
      {LinkKind::OpticalInterconnect, "OPTICAL_INTERCONNECT"},
  }};
  return parse_enum(kTable, text, out);
}

bool link_state_from_string(std::string_view text, LinkState& out) noexcept {
  static const std::array<std::pair<LinkState, const char*>, 5> kTable{{
      {LinkState::Unknown, "UNKNOWN"},
      {LinkState::Up, "UP"},
      {LinkState::Degraded, "DEGRADED"},
      {LinkState::Down, "DOWN"},
      {LinkState::Unsupported, "UNSUPPORTED"},
  }};
  return parse_enum(kTable, text, out);
}

bool link_kind_supported(LinkKind kind) noexcept {
  return kind == LinkKind::LoopbackTcp || kind == LinkKind::SyntheticModel;
}

const char* link_kind_support_note(LinkKind kind) noexcept {
  switch (kind) {
    case LinkKind::LoopbackTcp:
      return "real framed transport over a real TCP socket";
    case LinkKind::SyntheticModel:
      return "SYNTHETIC: declared topology, no transport is driven or observed";
    case LinkKind::OpticalInterconnect:
      return "UNSUPPORTED: this runtime owns no optical hardware control path";
    case LinkKind::Unknown:
      return "UNKNOWN: no evidence describes this link";
  }
  return "UNKNOWN: no evidence describes this link";
}

int ContractRecord::side_of(const ClusterId& cluster) const noexcept {
  for (std::size_t i = 0; i < parties.size(); ++i) {
    if (parties[i].cluster == cluster) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

bool ContractRecord::both_consented() const noexcept {
  for (const auto& consent : consents) {
    if (!consent.has_value() || consent->decision != ConsentDecision::Accepted) {
      return false;
    }
  }
  return true;
}

bool PolicyRule::matches(const ClusterId& a, const ClusterId& b, const EndpointId& ea,
                         const EndpointId& eb) const noexcept {
  const bool cluster_a_ok = cluster_a.empty() || cluster_a == a;
  const bool cluster_b_ok = cluster_b.empty() || cluster_b == b;
  const bool endpoint_a_ok = endpoint_a.empty() || endpoint_a == ea;
  const bool endpoint_b_ok = endpoint_b.empty() || endpoint_b == eb;
  return cluster_a_ok && cluster_b_ok && endpoint_a_ok && endpoint_b_ok;
}

}  // namespace icf::model
