#include "icf/model/decision.hpp"

#include "icf/core/checked.hpp"
#include "icf/core/limits.hpp"

namespace icf::model {
namespace {

template <class Record, class EncodeFn>
void encode_list(const std::vector<Record>& records, ByteWriter& writer, EncodeFn encode) {
  const bool ok = writer.count(records.size());
  (void)ok;
  for (const Record& record : records) {
    encode(record, writer);
  }
}

Result<std::string> decode_text(ByteReader& reader) { return reader.blob(limits::kMaxStringField); }

Result<std::size_t> decode_count(ByteReader& reader, std::size_t bound) { return reader.count(bound); }

Result<std::uint64_t> decode_counter(ByteReader& reader, std::uint64_t bound) {
  Result<std::uint64_t> value = reader.u64();
  if (!value) {
    return value.status();
  }
  if (value.value() > bound) {
    return Status::make(Outcome::Overflow, "counter exceeds the maximum permitted value");
  }
  return value.value();
}

}  // namespace

const char* to_string(ReasonCode code) noexcept {
  switch (code) {
    case ReasonCode::None:
      return "NONE";
    case ReasonCode::EndpointsAreIdentical:
      return "ENDPOINTS_ARE_IDENTICAL";
    case ReasonCode::SourceEndpointNotRegistered:
      return "SOURCE_ENDPOINT_NOT_REGISTERED";
    case ReasonCode::TargetEndpointNotRegistered:
      return "TARGET_ENDPOINT_NOT_REGISTERED";
    case ReasonCode::SourceEndpointSuspended:
      return "SOURCE_ENDPOINT_SUSPENDED";
    case ReasonCode::TargetEndpointSuspended:
      return "TARGET_ENDPOINT_SUSPENDED";
    case ReasonCode::SourceEndpointRefused:
      return "SOURCE_ENDPOINT_REFUSED";
    case ReasonCode::TargetEndpointRefused:
      return "TARGET_ENDPOINT_REFUSED";
    case ReasonCode::ResourceUnknown:
      return "RESOURCE_UNKNOWN";
    case ReasonCode::ResourceUnsupported:
      return "RESOURCE_UNSUPPORTED";
    case ReasonCode::ResourceUnreachable:
      return "RESOURCE_UNREACHABLE";
    case ReasonCode::ResourcePartitioned:
      return "RESOURCE_PARTITIONED";
    case ReasonCode::PolicyAllowed:
      return "POLICY_ALLOWED";
    case ReasonCode::PolicyRefused:
      return "POLICY_REFUSED";
    case ReasonCode::PolicyMissingAllow:
      return "POLICY_MISSING_ALLOW";
    case ReasonCode::PolicyStaleGeneration:
      return "POLICY_STALE_GENERATION";
    case ReasonCode::ClusterUnknown:
      return "CLUSTER_UNKNOWN";
    case ReasonCode::ClusterSuspended:
      return "CLUSTER_SUSPENDED";
    case ReasonCode::ClusterDraining:
      return "CLUSTER_DRAINING";
    case ReasonCode::ClusterRetired:
      return "CLUSTER_RETIRED";
    case ReasonCode::ClusterGenerationConflict:
      return "CLUSTER_GENERATION_CONFLICT";
    case ReasonCode::ClusterConsentWithdrawn:
      return "CLUSTER_CONSENT_WITHDRAWN";
    case ReasonCode::IncarnationMismatch:
      return "INCARNATION_MISMATCH";
    case ReasonCode::GenerationStale:
      return "GENERATION_STALE";
    case ReasonCode::PolicyGenerationStale:
      return "POLICY_GENERATION_STALE";
    case ReasonCode::NoContract:
      return "NO_CONTRACT";
    case ReasonCode::ContractNotConsented:
      return "CONTRACT_NOT_CONSENTED";
    case ReasonCode::ContractRefused:
      return "CONTRACT_REFUSED";
    case ReasonCode::ContractWithdrawn:
      return "CONTRACT_WITHDRAWN";
    case ReasonCode::ContractExpired:
      return "CONTRACT_EXPIRED";
    case ReasonCode::ContractFenced:
      return "CONTRACT_FENCED";
    case ReasonCode::ConsentMismatch:
      return "CONSENT_MISMATCH";
    case ReasonCode::ConsentUnauthenticated:
      return "CONSENT_UNAUTHENTICATED";
    case ReasonCode::NoGrant:
      return "NO_GRANT";
    case ReasonCode::GrantNotCommitted:
      return "GRANT_NOT_COMMITTED";
    case ReasonCode::GrantNotAcknowledged:
      return "GRANT_NOT_ACKNOWLEDGED";
    case ReasonCode::GrantIndeterminate:
      return "GRANT_INDETERMINATE";
    case ReasonCode::GrantFenced:
      return "GRANT_FENCED";
    case ReasonCode::GrantExpired:
      return "GRANT_EXPIRED";
    case ReasonCode::GrantTermMismatch:
      return "GRANT_TERM_MISMATCH";
    case ReasonCode::GrantNeedsRevalidation:
      return "GRANT_NEEDS_REVALIDATION";
    case ReasonCode::GrantCapacityExceeded:
      return "GRANT_CAPACITY_EXCEEDED";
    case ReasonCode::PathAbsent:
      return "PATH_ABSENT";
    case ReasonCode::PathUnsupported:
      return "PATH_UNSUPPORTED";
    case ReasonCode::PathDown:
      return "PATH_DOWN";
    case ReasonCode::PathDegraded:
      return "PATH_DEGRADED";
    case ReasonCode::PathNotPermittedDegraded:
      return "PATH_NOT_PERMITTED_DEGRADED";
    case ReasonCode::LinkUnsupported:
      return "LINK_UNSUPPORTED";
    case ReasonCode::LinkDown:
      return "LINK_DOWN";
    case ReasonCode::LinkDegraded:
      return "LINK_DEGRADED";
    case ReasonCode::LinkUnknown:
      return "LINK_UNKNOWN";
    case ReasonCode::CapacityExhausted:
      return "CAPACITY_EXHAUSTED";
    case ReasonCode::EvidenceUnverified:
      return "EVIDENCE_UNVERIFIED";
    case ReasonCode::EvidenceRecoveredFromStore:
      return "EVIDENCE_RECOVERED_FROM_STORE";
    case ReasonCode::EvidenceIncomplete:
      return "EVIDENCE_INCOMPLETE";
    case ReasonCode::AuthorityRequired:
      return "AUTHORITY_REQUIRED";
    case ReasonCode::AuthoritySatisfied:
      return "AUTHORITY_SATISFIED";
  }
  return "NONE";
}

const char* to_string(FenceTrigger trigger) noexcept {
  switch (trigger) {
    case FenceTrigger::Manual:
      return "MANUAL";
    case FenceTrigger::ClusterReincarnation:
      return "CLUSTER_REINCARNATION";
    case FenceTrigger::ClusterWithdrawal:
      return "CLUSTER_WITHDRAWAL";
    case FenceTrigger::PolicyGenerationChange:
      return "POLICY_GENERATION_CHANGE";
    case FenceTrigger::CoordinatorReincarnation:
      return "COORDINATOR_REINCARNATION";
    case FenceTrigger::GrantRevocation:
      return "GRANT_REVOCATION";
    case FenceTrigger::LinkFailure:
      return "LINK_FAILURE";
    case FenceTrigger::GrantExpiry:
      return "GRANT_EXPIRY";
  }
  return "MANUAL";
}

const char* to_string(FenceTarget target) noexcept {
  switch (target) {
    case FenceTarget::Grant:
      return "GRANT";
    case FenceTarget::Contract:
      return "CONTRACT";
    case FenceTarget::Reservation:
      return "RESERVATION";
  }
  return "GRANT";
}

void encode_decision(const Decision& decision, ByteWriter& writer) {
  writer.u16(static_cast<std::uint16_t>(decision.outcome));
  encode_list(decision.reasons, writer,
              [](const ReasonCode& code, ByteWriter& out) { out.u16(static_cast<std::uint16_t>(code)); });
  writer.uuid(decision.contract.uuid());
  writer.uuid(decision.grant.uuid());
  for (const AuthorityDomainId& authority : decision.authorities) {
    writer.blob(authority.str());
  }
  writer.u64(decision.term.value());
  writer.uuid(decision.coordinator.uuid());
  writer.digest(decision.terms_digest);
  writer.digest(decision.view_digest);
  writer.u64(decision.capacity.value());
  encode_list(decision.paths, writer, [](const PathId& id, ByteWriter& out) { out.blob(id.str()); });
  encode_list(decision.edges, writer, [](const EdgeId& id, ByteWriter& out) { out.blob(id.str()); });
  writer.boolean(decision.degraded);
  writer.i64(decision.decided_at.unix_nanos());
  writer.blob(decision.detail);
}

Result<Decision> decode_decision(ByteReader& reader) {
  Decision decision;
  Result<std::uint16_t> outcome = reader.u16();
  if (!outcome) {
    return outcome.status();
  }
  if (outcome.value() > static_cast<std::uint16_t>(Outcome::Internal)) {
    return invalid("decision outcome is out of range");
  }
  decision.outcome = static_cast<Outcome>(outcome.value());

  Result<std::size_t> reason_count = decode_count(reader, limits::kMaxDecisionReasons);
  if (!reason_count) {
    return reason_count.status();
  }
  decision.reasons.reserve(reason_count.value());
  for (std::size_t i = 0; i < reason_count.value(); ++i) {
    Result<std::uint16_t> code = reader.u16();
    if (!code) {
      return code.status();
    }
    if (code.value() > static_cast<std::uint16_t>(ReasonCode::AuthoritySatisfied)) {
      return invalid("decision reason code is out of range");
    }
    decision.reasons.push_back(static_cast<ReasonCode>(code.value()));
  }
  Result<Uuid> contract = reader.uuid();
  if (!contract) {
    return contract.status();
  }
  Result<Uuid> grant = reader.uuid();
  if (!grant) {
    return grant.status();
  }
  decision.contract = ContractId::from_uuid(contract.value());
  decision.grant = GrantId::from_uuid(grant.value());
  for (AuthorityDomainId& authority : decision.authorities) {
    Result<std::string> text = reader.blob(limits::kMaxNameLength);
    if (!text) {
      return text.status();
    }
    if (text.value().empty()) {
      authority = AuthorityDomainId{};
      continue;
    }
    Result<AuthorityDomainId> parsed = AuthorityDomainId::parse(text.value());
    if (!parsed) {
      return parsed.status();
    }
    authority = parsed.value();
  }
  Result<std::uint64_t> term = decode_counter(reader, limits::kMaxGeneration);
  if (!term) {
    return term.status();
  }
  decision.term = Term(term.value());
  Result<Uuid> coordinator = reader.uuid();
  if (!coordinator) {
    return coordinator.status();
  }
  decision.coordinator = IncarnationId::from_uuid(coordinator.value());
  Result<Digest> terms = reader.digest();
  if (!terms) {
    return terms.status();
  }
  decision.terms_digest = terms.value();
  Result<Digest> view = reader.digest();
  if (!view) {
    return view.status();
  }
  decision.view_digest = view.value();
  Result<std::uint64_t> capacity = decode_counter(reader, limits::kMaxCapacity);
  if (!capacity) {
    return capacity.status();
  }
  decision.capacity = CapacityUnits(capacity.value());

  Result<std::size_t> path_count = decode_count(reader, limits::kMaxDecisionPaths);
  if (!path_count) {
    return path_count.status();
  }
  for (std::size_t i = 0; i < path_count.value(); ++i) {
    Result<std::string> text = reader.blob(limits::kMaxNameLength);
    if (!text) {
      return text.status();
    }
    Result<PathId> parsed = PathId::parse(text.value());
    if (!parsed) {
      return parsed.status();
    }
    decision.paths.push_back(parsed.value());
  }
  Result<std::size_t> edge_count = decode_count(reader, limits::kMaxEdges);
  if (!edge_count) {
    return edge_count.status();
  }
  for (std::size_t i = 0; i < edge_count.value(); ++i) {
    Result<std::string> text = reader.blob(limits::kMaxNameLength);
    if (!text) {
      return text.status();
    }
    Result<EdgeId> parsed = EdgeId::parse(text.value());
    if (!parsed) {
      return parsed.status();
    }
    decision.edges.push_back(parsed.value());
  }
  Result<bool> degraded = reader.boolean();
  if (!degraded) {
    return degraded.status();
  }
  decision.degraded = degraded.value();
  Result<std::int64_t> decided_at = reader.i64();
  if (!decided_at) {
    return decided_at.status();
  }
  decision.decided_at = Timestamp::from_unix_nanos(decided_at.value());
  Result<std::string> detail = decode_text(reader);
  if (!detail) {
    return detail.status();
  }
  decision.detail = std::move(detail.value());
  return decision;
}

void encode_fence_plan(const FencePlan& plan, ByteWriter& writer) {
  writer.u8(static_cast<std::uint8_t>(plan.trigger));
  writer.blob(plan.cluster.str());
  writer.uuid(plan.incarnation.uuid());
  writer.uuid(plan.previous_incarnation.uuid());
  writer.u64(plan.generation.value());
  writer.u64(plan.term.value());
  writer.digest(plan.view_digest);
  encode_list(plan.actions, writer, [](const FenceAction& action, ByteWriter& out) {
    out.u8(static_cast<std::uint8_t>(action.target));
    out.uuid(action.grant.uuid());
    out.uuid(action.contract.uuid());
    out.uuid(action.reservation.uuid());
    out.u16(static_cast<std::uint16_t>(action.reason));
  });
  writer.blob(plan.detail);
}

Result<FencePlan> decode_fence_plan(ByteReader& reader) {
  FencePlan plan;
  Result<std::uint8_t> trigger = reader.u8();
  if (!trigger) {
    return trigger.status();
  }
  if (trigger.value() > static_cast<std::uint8_t>(FenceTrigger::GrantExpiry)) {
    return invalid("fence trigger is out of range");
  }
  plan.trigger = static_cast<FenceTrigger>(trigger.value());
  Result<std::string> cluster = reader.blob(limits::kMaxNameLength);
  if (!cluster) {
    return cluster.status();
  }
  if (!cluster.value().empty()) {
    Result<ClusterId> parsed = ClusterId::parse(cluster.value());
    if (!parsed) {
      return parsed.status();
    }
    plan.cluster = parsed.value();
  }
  Result<Uuid> incarnation = reader.uuid();
  if (!incarnation) {
    return incarnation.status();
  }
  Result<Uuid> previous = reader.uuid();
  if (!previous) {
    return previous.status();
  }
  plan.incarnation = IncarnationId::from_uuid(incarnation.value());
  plan.previous_incarnation = IncarnationId::from_uuid(previous.value());
  Result<std::uint64_t> generation = decode_counter(reader, limits::kMaxGeneration);
  if (!generation) {
    return generation.status();
  }
  plan.generation = Generation(generation.value());
  Result<std::uint64_t> term = decode_counter(reader, limits::kMaxGeneration);
  if (!term) {
    return term.status();
  }
  plan.term = Term(term.value());
  Result<Digest> view = reader.digest();
  if (!view) {
    return view.status();
  }
  plan.view_digest = view.value();
  Result<std::size_t> action_count = decode_count(reader, limits::kMaxFencePlanEntries);
  if (!action_count) {
    return action_count.status();
  }
  plan.actions.reserve(action_count.value());
  for (std::size_t i = 0; i < action_count.value(); ++i) {
    FenceAction action;
    Result<std::uint8_t> target = reader.u8();
    if (!target) {
      return target.status();
    }
    if (target.value() > static_cast<std::uint8_t>(FenceTarget::Reservation)) {
      return invalid("fence target is out of range");
    }
    action.target = static_cast<FenceTarget>(target.value());
    Result<Uuid> grant = reader.uuid();
    if (!grant) {
      return grant.status();
    }
    Result<Uuid> contract = reader.uuid();
    if (!contract) {
      return contract.status();
    }
    Result<Uuid> reservation = reader.uuid();
    if (!reservation) {
      return reservation.status();
    }
    Result<std::uint16_t> reason = reader.u16();
    if (!reason) {
      return reason.status();
    }
    if (reason.value() > static_cast<std::uint16_t>(ReasonCode::AuthoritySatisfied)) {
      return invalid("fence reason code is out of range");
    }
    action.grant = GrantId::from_uuid(grant.value());
    action.contract = ContractId::from_uuid(contract.value());
    action.reservation = ReservationId::from_uuid(reservation.value());
    action.reason = static_cast<ReasonCode>(reason.value());
    plan.actions.push_back(action);
  }
  Result<std::string> detail = decode_text(reader);
  if (!detail) {
    return detail.status();
  }
  plan.detail = std::move(detail.value());
  return plan;
}

void encode_accounting(const AccountingEntry& entry, ByteWriter& writer) {
  writer.uuid(entry.grant.uuid());
  writer.uuid(entry.contract.uuid());
  writer.blob(entry.endpoint.str());
  writer.blob(entry.cluster.str());
  writer.u64(entry.reserved.value());
  writer.u64(entry.released.value());
  writer.boolean(entry.closed);
}

Result<AccountingEntry> decode_accounting(ByteReader& reader) {
  AccountingEntry entry;
  Result<Uuid> grant = reader.uuid();
  if (!grant) {
    return grant.status();
  }
  Result<Uuid> contract = reader.uuid();
  if (!contract) {
    return contract.status();
  }
  Result<std::string> endpoint = reader.blob(limits::kMaxNameLength);
  if (!endpoint) {
    return endpoint.status();
  }
  Result<std::string> cluster = reader.blob(limits::kMaxNameLength);
  if (!cluster) {
    return cluster.status();
  }
  Result<std::uint64_t> reserved = decode_counter(reader, limits::kMaxCapacity);
  if (!reserved) {
    return reserved.status();
  }
  Result<std::uint64_t> released = decode_counter(reader, limits::kMaxCapacity);
  if (!released) {
    return released.status();
  }
  Result<bool> closed = reader.boolean();
  if (!closed) {
    return closed.status();
  }
  entry.grant = GrantId::from_uuid(grant.value());
  entry.contract = ContractId::from_uuid(contract.value());
  if (!endpoint.value().empty()) {
    Result<EndpointId> parsed = EndpointId::parse(endpoint.value());
    if (!parsed) {
      return parsed.status();
    }
    entry.endpoint = parsed.value();
  }
  if (!cluster.value().empty()) {
    Result<ClusterId> parsed = ClusterId::parse(cluster.value());
    if (!parsed) {
      return parsed.status();
    }
    entry.cluster = parsed.value();
  }
  entry.reserved = CapacityUnits(reserved.value());
  entry.released = CapacityUnits(released.value());
  entry.closed = closed.value();
  return entry;
}

void encode_status(const CoordinatorStatus& status, ByteWriter& writer) {
  writer.blob(status.domain.str());
  writer.uuid(status.incarnation.uuid());
  writer.u64(status.term.value());
  writer.i64(status.started_at.unix_nanos());
  writer.u64(status.uptime_nanos);
  writer.digest(status.view_digest);
  writer.u64(status.revision.value());
  writer.boolean(status.recovered_from_store);
  writer.u64(status.recovered_records);
  writer.u64(status.truncations_recovered);
  for (const std::size_t value : {status.clusters, status.endpoints, status.links, status.paths, status.contracts,
                                  status.grants, status.reservations, status.policies, status.audit,
                                  status.connected_agents}) {
    writer.u64(static_cast<std::uint64_t>(value));
  }
  for (const std::uint64_t value : {status.commits, status.fences, status.refusals, status.revalidations,
                                    status.rejected_replays, status.rejected_frames}) {
    writer.u64(value);
  }
  writer.blob(status.store_path);
}

Result<CoordinatorStatus> decode_status(ByteReader& reader) {
  CoordinatorStatus status;
  Result<std::string> domain = reader.blob(limits::kMaxNameLength);
  if (!domain) {
    return domain.status();
  }
  if (!domain.value().empty()) {
    Result<AuthorityDomainId> parsed = AuthorityDomainId::parse(domain.value());
    if (!parsed) {
      return parsed.status();
    }
    status.domain = parsed.value();
  }
  Result<Uuid> incarnation = reader.uuid();
  if (!incarnation) {
    return incarnation.status();
  }
  status.incarnation = IncarnationId::from_uuid(incarnation.value());
  Result<std::uint64_t> term = decode_counter(reader, limits::kMaxGeneration);
  if (!term) {
    return term.status();
  }
  status.term = Term(term.value());
  Result<std::int64_t> started_at = reader.i64();
  if (!started_at) {
    return started_at.status();
  }
  status.started_at = Timestamp::from_unix_nanos(started_at.value());
  Result<std::uint64_t> uptime = reader.u64();
  if (!uptime) {
    return uptime.status();
  }
  status.uptime_nanos = uptime.value();
  Result<Digest> view = reader.digest();
  if (!view) {
    return view.status();
  }
  status.view_digest = view.value();
  Result<std::uint64_t> revision = decode_counter(reader, limits::kMaxGeneration);
  if (!revision) {
    return revision.status();
  }
  status.revision = Revision(revision.value());
  Result<bool> recovered = reader.boolean();
  if (!recovered) {
    return recovered.status();
  }
  status.recovered_from_store = recovered.value();
  Result<std::uint64_t> records = reader.u64();
  if (!records) {
    return records.status();
  }
  status.recovered_records = records.value();
  Result<std::uint64_t> truncations = reader.u64();
  if (!truncations) {
    return truncations.status();
  }
  status.truncations_recovered = truncations.value();
  std::size_t* counts[] = {&status.clusters,        &status.endpoints,    &status.links,
                           &status.paths,          &status.contracts,    &status.grants,
                           &status.reservations,   &status.policies,     &status.audit,
                           &status.connected_agents};
  for (std::size_t* target : counts) {
    Result<std::uint64_t> value = reader.u64();
    if (!value) {
      return value.status();
    }
    std::size_t narrowed = 0;
    if (!checked::to_size(value.value(), narrowed)) {
      return Status::make(Outcome::Overflow, "status counter does not fit in the platform size type");
    }
    *target = narrowed;
  }
  std::uint64_t* counters[] = {&status.commits,          &status.fences,          &status.refusals,
                               &status.revalidations,   &status.rejected_replays, &status.rejected_frames};
  for (std::uint64_t* target : counters) {
    Result<std::uint64_t> value = reader.u64();
    if (!value) {
      return value.status();
    }
    *target = value.value();
  }
  Result<std::string> store = reader.blob(limits::kMaxStringField);
  if (!store) {
    return store.status();
  }
  status.store_path = std::move(store.value());
  return status;
}

}  // namespace icf::model
