#include <algorithm>
#include <utility>

#include "icf/core/checked.hpp"
#include "icf/core/limits.hpp"
#include "icf/model/registry.hpp"

namespace icf::model {
namespace {

constexpr std::size_t kMaxText = limits::kMaxStringField;

Result<std::string> decode_text(ByteReader& reader) { return reader.blob(kMaxText); }

template <class Name>
Result<Name> decode_name(ByteReader& reader, std::size_t max_length) {
  Result<std::string> text = reader.blob(max_length);
  if (!text) {
    return text.status();
  }
  return Name::parse(text.value());
}

Result<Uuid> decode_uuid(ByteReader& reader) { return reader.uuid(); }

template <class Enum>
Result<Enum> decode_enum8(ByteReader& reader, std::uint8_t max_value) {
  Result<std::uint8_t> raw = reader.u8();
  if (!raw) {
    return raw.status();
  }
  if (raw.value() > max_value) {
    return invalid("enumeration value is out of range");
  }
  return static_cast<Enum>(raw.value());
}

template <class Enum>
Result<Enum> decode_enum16(ByteReader& reader, std::uint16_t max_value) {
  Result<std::uint16_t> raw = reader.u16();
  if (!raw) {
    return raw.status();
  }
  if (raw.value() > max_value) {
    return invalid("enumeration value is out of range");
  }
  return static_cast<Enum>(raw.value());
}

Result<std::uint64_t> decode_counter(ByteReader& reader, std::uint64_t max_value) {
  Result<std::uint64_t> raw = reader.u64();
  if (!raw) {
    return raw.status();
  }
  if (raw.value() > max_value) {
    return Status::make(Outcome::Overflow, "counter exceeds the maximum permitted value");
  }
  return raw.value();
}

void encode_provenance(const Provenance& provenance, ByteWriter& writer) {
  writer.u8(static_cast<std::uint8_t>(provenance.source));
  writer.u8(static_cast<std::uint8_t>(provenance.verification));
  writer.i64(provenance.observed_at.unix_nanos());
  writer.u64(provenance.revision.value());
  writer.uuid(provenance.session.uuid());
  writer.digest(provenance.evidence_digest);
}

Result<Provenance> decode_provenance(ByteReader& reader) {
  Provenance provenance;
  Result<EvidenceSource> source = decode_enum8<EvidenceSource>(reader, 5);
  if (!source) {
    return source.status();
  }
  Result<VerificationState> verification = decode_enum8<VerificationState>(reader, 4);
  if (!verification) {
    return verification.status();
  }
  Result<std::int64_t> observed = reader.i64();
  if (!observed) {
    return observed.status();
  }
  Result<std::uint64_t> revision = decode_counter(reader, limits::kMaxGeneration);
  if (!revision) {
    return revision.status();
  }
  Result<Uuid> session = reader.uuid();
  if (!session) {
    return session.status();
  }
  Result<Digest> digest = reader.digest();
  if (!digest) {
    return digest.status();
  }
  provenance.source = source.value();
  provenance.verification = verification.value();
  provenance.observed_at = Timestamp::from_unix_nanos(observed.value());
  provenance.revision = Revision(revision.value());
  provenance.session = SessionToken::from_uuid(session.value());
  provenance.evidence_digest = digest.value();
  return provenance;
}

void encode_endpoint(const EndpointRecord& record, ByteWriter& writer) {
  writer.blob(record.id.str());
  writer.blob(record.cluster.str());
  writer.blob(record.scope.str());
  writer.u64(record.capacity.value());
  writer.u64(record.reserved.value());
  writer.u64(record.policy_generation.value());
  writer.u8(static_cast<std::uint8_t>(record.state));
  writer.boolean(record.inter_cluster_allowed);
  writer.boolean(record.permits_degraded);
  encode_provenance(record.provenance, writer);
}

Result<EndpointRecord> decode_endpoint(ByteReader& reader) {
  EndpointRecord record;
  Result<EndpointId> id = decode_name<EndpointId>(reader, limits::kMaxNameLength);
  if (!id) {
    return id.status();
  }
  Result<ClusterId> cluster = decode_name<ClusterId>(reader, limits::kMaxNameLength);
  if (!cluster) {
    return cluster.status();
  }
  Result<ScopeName> scope = decode_name<ScopeName>(reader, limits::kMaxScopeLength);
  if (!scope) {
    return scope.status();
  }
  Result<std::uint64_t> capacity = decode_counter(reader, limits::kMaxCapacity);
  if (!capacity) {
    return capacity.status();
  }
  Result<std::uint64_t> reserved = decode_counter(reader, limits::kMaxCapacity);
  if (!reserved) {
    return reserved.status();
  }
  Result<std::uint64_t> policy = decode_counter(reader, limits::kMaxGeneration);
  if (!policy) {
    return policy.status();
  }
  Result<EndpointState> state = decode_enum8<EndpointState>(reader, 4);
  if (!state) {
    return state.status();
  }
  Result<bool> allowed = reader.boolean();
  if (!allowed) {
    return allowed.status();
  }
  Result<bool> degraded = reader.boolean();
  if (!degraded) {
    return degraded.status();
  }
  Result<Provenance> provenance = decode_provenance(reader);
  if (!provenance) {
    return provenance.status();
  }
  record.id = id.value();
  record.cluster = cluster.value();
  record.scope = scope.value();
  record.capacity = CapacityUnits(capacity.value());
  record.reserved = CapacityUnits(reserved.value());
  record.policy_generation = PolicyGeneration(policy.value());
  record.state = state.value();
  record.inter_cluster_allowed = allowed.value();
  record.permits_degraded = degraded.value();
  record.provenance = provenance.value();
  return record;
}

void encode_consent(const ConsentRecord& consent, ByteWriter& writer) {
  writer.blob(consent.cluster.str());
  writer.blob(consent.endpoint.str());
  writer.uuid(consent.incarnation.uuid());
  writer.u64(consent.generation.value());
  writer.u64(consent.policy_generation.value());
  writer.u64(consent.agent_term.value());
  writer.digest(consent.terms_digest);
  writer.u8(static_cast<std::uint8_t>(consent.decision));
  writer.i64(consent.decided_at.unix_nanos());
  writer.uuid(consent.session.uuid());
  writer.u8(static_cast<std::uint8_t>(consent.authenticity));
  writer.blob(consent.reason);
}

Result<ConsentRecord> decode_consent(ByteReader& reader) {
  ConsentRecord consent;
  Result<ClusterId> cluster = decode_name<ClusterId>(reader, limits::kMaxNameLength);
  if (!cluster) {
    return cluster.status();
  }
  Result<EndpointId> endpoint = decode_name<EndpointId>(reader, limits::kMaxNameLength);
  if (!endpoint) {
    return endpoint.status();
  }
  Result<Uuid> incarnation = reader.uuid();
  if (!incarnation) {
    return incarnation.status();
  }
  Result<std::uint64_t> generation = decode_counter(reader, limits::kMaxGeneration);
  if (!generation) {
    return generation.status();
  }
  Result<std::uint64_t> policy = decode_counter(reader, limits::kMaxGeneration);
  if (!policy) {
    return policy.status();
  }
  Result<std::uint64_t> term = decode_counter(reader, limits::kMaxGeneration);
  if (!term) {
    return term.status();
  }
  Result<Digest> terms_digest = reader.digest();
  if (!terms_digest) {
    return terms_digest.status();
  }
  Result<ConsentDecision> decision = decode_enum8<ConsentDecision>(reader, 1);
  if (!decision) {
    return decision.status();
  }
  Result<std::int64_t> decided_at = reader.i64();
  if (!decided_at) {
    return decided_at.status();
  }
  Result<Uuid> session = reader.uuid();
  if (!session) {
    return session.status();
  }
  Result<TransportAuthenticity> authenticity = decode_enum8<TransportAuthenticity>(reader, 1);
  if (!authenticity) {
    return authenticity.status();
  }
  Result<std::string> reason = decode_text(reader);
  if (!reason) {
    return reason.status();
  }
  consent.cluster = cluster.value();
  consent.endpoint = endpoint.value();
  consent.incarnation = IncarnationId::from_uuid(incarnation.value());
  consent.generation = Generation(generation.value());
  consent.policy_generation = PolicyGeneration(policy.value());
  consent.agent_term = Term(term.value());
  consent.terms_digest = terms_digest.value();
  consent.decision = decision.value();
  consent.decided_at = Timestamp::from_unix_nanos(decided_at.value());
  consent.session = SessionToken::from_uuid(session.value());
  consent.authenticity = authenticity.value();
  consent.reason = std::move(reason.value());
  return consent;
}

}  // namespace

void encode_cluster(const ClusterRecord& record, ByteWriter& writer) {
  writer.blob(record.id.str());
  writer.blob(record.domain.str());
  writer.uuid(record.incarnation.uuid());
  writer.u64(record.generation.value());
  writer.u64(record.policy_generation.value());
  writer.u8(static_cast<std::uint8_t>(record.state));
  writer.boolean(record.consent_withdrawn);
  writer.i64(record.last_seen.unix_nanos());
  const bool endpoints_ok = writer.count(record.endpoints.size());
  (void)endpoints_ok;  // bounded by Registry::put_cluster before encoding
  for (const EndpointRecord& endpoint : record.endpoints) {
    encode_endpoint(endpoint, writer);
  }
  writer.digest(record.content_digest);
  writer.boolean(record.generation_conflict);
  writer.boolean(record.conflicting_generation.has_value());
  writer.u64(record.conflicting_generation.has_value() ? record.conflicting_generation->value() : 0);
  writer.u64(record.revision.value());
  encode_provenance(record.provenance, writer);
  writer.u64(record.incarnation_changes);
}

Result<ClusterRecord> decode_cluster(ByteReader& reader) {
  ClusterRecord record;
  Result<ClusterId> id = decode_name<ClusterId>(reader, limits::kMaxNameLength);
  if (!id) {
    return id.status();
  }
  Result<AuthorityDomainId> domain = decode_name<AuthorityDomainId>(reader, limits::kMaxNameLength);
  if (!domain) {
    return domain.status();
  }
  Result<Uuid> incarnation = reader.uuid();
  if (!incarnation) {
    return incarnation.status();
  }
  Result<std::uint64_t> generation = decode_counter(reader, limits::kMaxGeneration);
  if (!generation) {
    return generation.status();
  }
  Result<std::uint64_t> policy = decode_counter(reader, limits::kMaxGeneration);
  if (!policy) {
    return policy.status();
  }
  Result<ClusterState> state = decode_enum8<ClusterState>(reader, 4);
  if (!state) {
    return state.status();
  }
  Result<bool> withdrawn = reader.boolean();
  if (!withdrawn) {
    return withdrawn.status();
  }
  Result<std::int64_t> last_seen = reader.i64();
  if (!last_seen) {
    return last_seen.status();
  }
  Result<std::size_t> endpoint_count = reader.count(limits::kMaxEndpointsPerCluster);
  if (!endpoint_count) {
    return endpoint_count.status();
  }
  record.endpoints.reserve(endpoint_count.value());
  for (std::size_t i = 0; i < endpoint_count.value(); ++i) {
    Result<EndpointRecord> endpoint = decode_endpoint(reader);
    if (!endpoint) {
      return endpoint.status();
    }
    record.endpoints.push_back(std::move(endpoint.value()));
  }
  std::sort(record.endpoints.begin(), record.endpoints.end(),
            [](const EndpointRecord& a, const EndpointRecord& b) { return a.id < b.id; });
  for (std::size_t i = 1; i < record.endpoints.size(); ++i) {
    if (record.endpoints[i - 1].id == record.endpoints[i].id) {
      return invalid("cluster record contains a duplicate endpoint identity");
    }
  }
  Result<Digest> content = reader.digest();
  if (!content) {
    return content.status();
  }
  Result<bool> conflict = reader.boolean();
  if (!conflict) {
    return conflict.status();
  }
  Result<bool> has_conflict_generation = reader.boolean();
  if (!has_conflict_generation) {
    return has_conflict_generation.status();
  }
  Result<std::uint64_t> conflict_generation = decode_counter(reader, limits::kMaxGeneration);
  if (!conflict_generation) {
    return conflict_generation.status();
  }
  Result<std::uint64_t> revision = decode_counter(reader, limits::kMaxGeneration);
  if (!revision) {
    return revision.status();
  }
  Result<Provenance> provenance = decode_provenance(reader);
  if (!provenance) {
    return provenance.status();
  }
  Result<std::uint64_t> incarnation_changes = decode_counter(reader, limits::kMaxGeneration);
  if (!incarnation_changes) {
    return incarnation_changes.status();
  }

  record.id = id.value();
  record.domain = domain.value();
  record.incarnation = IncarnationId::from_uuid(incarnation.value());
  record.generation = Generation(generation.value());
  record.policy_generation = PolicyGeneration(policy.value());
  record.state = state.value();
  record.consent_withdrawn = withdrawn.value();
  record.last_seen = Timestamp::from_unix_nanos(last_seen.value());
  record.content_digest = content.value();
  record.generation_conflict = conflict.value();
  if (has_conflict_generation.value()) {
    record.conflicting_generation = Generation(conflict_generation.value());
  }
  record.revision = Revision(revision.value());
  record.provenance = provenance.value();
  record.incarnation_changes = incarnation_changes.value();
  return record;
}

void encode_link(const LinkRecord& record, ByteWriter& writer) {
  writer.blob(record.id.str());
  writer.blob(record.a.str());
  writer.blob(record.b.str());
  writer.u16(static_cast<std::uint16_t>(record.kind));
  writer.u8(static_cast<std::uint8_t>(record.state));
  writer.u64(record.capacity.value());
  writer.u64(record.reserved.value());
  writer.u32(record.latency_micros);
  writer.u64(record.revision.value());
  encode_provenance(record.provenance, writer);
}

Result<LinkRecord> decode_link(ByteReader& reader) {
  LinkRecord record;
  Result<EdgeId> id = decode_name<EdgeId>(reader, limits::kMaxNameLength);
  if (!id) {
    return id.status();
  }
  Result<EndpointId> a = decode_name<EndpointId>(reader, limits::kMaxNameLength);
  if (!a) {
    return a.status();
  }
  Result<EndpointId> b = decode_name<EndpointId>(reader, limits::kMaxNameLength);
  if (!b) {
    return b.status();
  }
  Result<LinkKind> kind = decode_enum16<LinkKind>(reader, 3);
  if (!kind) {
    return kind.status();
  }
  Result<LinkState> state = decode_enum8<LinkState>(reader, 4);
  if (!state) {
    return state.status();
  }
  Result<std::uint64_t> capacity = decode_counter(reader, limits::kMaxCapacity);
  if (!capacity) {
    return capacity.status();
  }
  Result<std::uint64_t> reserved = decode_counter(reader, limits::kMaxCapacity);
  if (!reserved) {
    return reserved.status();
  }
  Result<std::uint32_t> latency = reader.u32();
  if (!latency) {
    return latency.status();
  }
  Result<std::uint64_t> revision = decode_counter(reader, limits::kMaxGeneration);
  if (!revision) {
    return revision.status();
  }
  Result<Provenance> provenance = decode_provenance(reader);
  if (!provenance) {
    return provenance.status();
  }
  record.id = id.value();
  record.a = a.value();
  record.b = b.value();
  record.kind = kind.value();
  record.state = state.value();
  record.capacity = CapacityUnits(capacity.value());
  record.reserved = CapacityUnits(reserved.value());
  record.latency_micros = latency.value();
  record.revision = Revision(revision.value());
  record.provenance = provenance.value();
  return record;
}

void encode_path(const PathRecord& record, ByteWriter& writer) {
  writer.blob(record.id.str());
  writer.blob(record.a.str());
  writer.blob(record.b.str());
  const bool hops_ok = writer.count(record.hops.size());
  (void)hops_ok;
  for (const EdgeId& hop : record.hops) {
    writer.blob(hop.str());
  }
  writer.u64(record.bottleneck.value());
  writer.u8(static_cast<std::uint8_t>(record.state));
  writer.u64(record.revision.value());
  encode_provenance(record.provenance, writer);
  writer.boolean(record.contains_unsupported_edge);
}

Result<PathRecord> decode_path(ByteReader& reader) {
  PathRecord record;
  Result<PathId> id = decode_name<PathId>(reader, limits::kMaxNameLength);
  if (!id) {
    return id.status();
  }
  Result<EndpointId> a = decode_name<EndpointId>(reader, limits::kMaxNameLength);
  if (!a) {
    return a.status();
  }
  Result<EndpointId> b = decode_name<EndpointId>(reader, limits::kMaxNameLength);
  if (!b) {
    return b.status();
  }
  Result<std::size_t> hop_count = reader.count(limits::kMaxPathHops);
  if (!hop_count) {
    return hop_count.status();
  }
  record.hops.reserve(hop_count.value());
  for (std::size_t i = 0; i < hop_count.value(); ++i) {
    Result<EdgeId> hop = decode_name<EdgeId>(reader, limits::kMaxNameLength);
    if (!hop) {
      return hop.status();
    }
    record.hops.push_back(hop.value());
  }
  Result<std::uint64_t> bottleneck = decode_counter(reader, limits::kMaxCapacity);
  if (!bottleneck) {
    return bottleneck.status();
  }
  Result<PathState> state = decode_enum8<PathState>(reader, 3);
  if (!state) {
    return state.status();
  }
  Result<std::uint64_t> revision = decode_counter(reader, limits::kMaxGeneration);
  if (!revision) {
    return revision.status();
  }
  Result<Provenance> provenance = decode_provenance(reader);
  if (!provenance) {
    return provenance.status();
  }
  Result<bool> unsupported = reader.boolean();
  if (!unsupported) {
    return unsupported.status();
  }
  record.id = id.value();
  record.a = a.value();
  record.b = b.value();
  record.bottleneck = CapacityUnits(bottleneck.value());
  record.state = state.value();
  record.revision = Revision(revision.value());
  record.provenance = provenance.value();
  record.contains_unsupported_edge = unsupported.value();
  return record;
}

void encode_policy(const PolicyRule& record, ByteWriter& writer) {
  writer.blob(record.id);
  writer.blob(record.owner.str());
  writer.blob(record.cluster_a.str());
  writer.blob(record.cluster_b.str());
  writer.blob(record.endpoint_a.str());
  writer.blob(record.endpoint_b.str());
  writer.u64(record.generation.value());
  writer.boolean(record.allow);
  writer.boolean(record.allow_degraded);
  writer.u64(record.max_capacity.value());
  writer.u64(record.revision.value());
  encode_provenance(record.provenance, writer);
}

Result<PolicyRule> decode_policy(ByteReader& reader) {
  PolicyRule record;
  Result<std::string> id = decode_text(reader);
  if (!id) {
    return id.status();
  }
  if (id.value().empty() || id.value().size() > limits::kMaxNameLength) {
    return invalid("policy rule identity has an invalid length");
  }
  Result<AuthorityDomainId> owner = decode_name<AuthorityDomainId>(reader, limits::kMaxNameLength);
  if (!owner) {
    return owner.status();
  }
  auto optional_cluster = [&reader](ClusterId& target) -> Status {
    Result<std::string> text = reader.blob(limits::kMaxNameLength);
    if (!text) {
      return text.status();
    }
    if (text.value().empty()) {
      target = ClusterId{};
      return Status::ok();
    }
    Result<ClusterId> parsed = ClusterId::parse(text.value());
    if (!parsed) {
      return parsed.status();
    }
    target = parsed.value();
    return Status::ok();
  };
  auto optional_endpoint = [&reader](EndpointId& target) -> Status {
    Result<std::string> text = reader.blob(limits::kMaxNameLength);
    if (!text) {
      return text.status();
    }
    if (text.value().empty()) {
      target = EndpointId{};
      return Status::ok();
    }
    Result<EndpointId> parsed = EndpointId::parse(text.value());
    if (!parsed) {
      return parsed.status();
    }
    target = parsed.value();
    return Status::ok();
  };

  Status status = optional_cluster(record.cluster_a);
  if (!status) {
    return status;
  }
  status = optional_cluster(record.cluster_b);
  if (!status) {
    return status;
  }
  status = optional_endpoint(record.endpoint_a);
  if (!status) {
    return status;
  }
  status = optional_endpoint(record.endpoint_b);
  if (!status) {
    return status;
  }
  Result<std::uint64_t> generation = decode_counter(reader, limits::kMaxGeneration);
  if (!generation) {
    return generation.status();
  }
  Result<bool> allow = reader.boolean();
  if (!allow) {
    return allow.status();
  }
  Result<bool> degraded = reader.boolean();
  if (!degraded) {
    return degraded.status();
  }
  Result<std::uint64_t> max_capacity = decode_counter(reader, limits::kMaxCapacity);
  if (!max_capacity) {
    return max_capacity.status();
  }
  Result<std::uint64_t> revision = decode_counter(reader, limits::kMaxGeneration);
  if (!revision) {
    return revision.status();
  }
  Result<Provenance> provenance = decode_provenance(reader);
  if (!provenance) {
    return provenance.status();
  }
  record.id = std::move(id.value());
  record.owner = owner.value();
  record.generation = PolicyGeneration(generation.value());
  record.allow = allow.value();
  record.allow_degraded = degraded.value();
  record.max_capacity = CapacityUnits(max_capacity.value());
  record.revision = Revision(revision.value());
  record.provenance = provenance.value();
  return record;
}

void encode_contract(const ContractRecord& record, ByteWriter& writer) {
  writer.uuid(record.id.uuid());
  for (const PartyRef& party : record.parties) {
    writer.blob(party.cluster.str());
    writer.blob(party.endpoint.str());
    writer.blob(party.domain.str());
  }
  writer.u64(record.capacity.value());
  writer.i64(record.lease_duration.nanos());
  writer.digest(record.terms_digest);
  writer.u8(static_cast<std::uint8_t>(record.state));
  for (const auto& consent : record.consents) {
    writer.boolean(consent.has_value());
    if (consent.has_value()) {
      encode_consent(*consent, writer);
    }
  }
  writer.i64(record.created_at.unix_nanos());
  writer.i64(record.updated_at.unix_nanos());
  writer.u64(record.revision.value());
  encode_provenance(record.provenance, writer);
}

Result<ContractRecord> decode_contract(ByteReader& reader) {
  ContractRecord record;
  Result<Uuid> id = reader.uuid();
  if (!id) {
    return id.status();
  }
  record.id = ContractId::from_uuid(id.value());
  for (PartyRef& party : record.parties) {
    Result<ClusterId> cluster = decode_name<ClusterId>(reader, limits::kMaxNameLength);
    if (!cluster) {
      return cluster.status();
    }
    Result<EndpointId> endpoint = decode_name<EndpointId>(reader, limits::kMaxNameLength);
    if (!endpoint) {
      return endpoint.status();
    }
    Result<AuthorityDomainId> domain = decode_name<AuthorityDomainId>(reader, limits::kMaxNameLength);
    if (!domain) {
      return domain.status();
    }
    party.cluster = cluster.value();
    party.endpoint = endpoint.value();
    party.domain = domain.value();
  }
  if (record.parties[0].cluster == record.parties[1].cluster) {
    return invalid("a contract must join two distinct cluster identities");
  }
  Result<std::uint64_t> capacity = decode_counter(reader, limits::kMaxCapacity);
  if (!capacity) {
    return capacity.status();
  }
  Result<std::int64_t> lease = reader.i64();
  if (!lease) {
    return lease.status();
  }
  if (lease.value() < 0 || static_cast<std::uint64_t>(lease.value()) > limits::kMaxDurationNanos) {
    return invalid("contract lease duration is out of range");
  }
  Result<Digest> terms = reader.digest();
  if (!terms) {
    return terms.status();
  }
  Result<ContractState> state = decode_enum8<ContractState>(reader, 7);
  if (!state) {
    return state.status();
  }
  for (auto& consent : record.consents) {
    Result<bool> present = reader.boolean();
    if (!present) {
      return present.status();
    }
    if (present.value()) {
      Result<ConsentRecord> decoded = decode_consent(reader);
      if (!decoded) {
        return decoded.status();
      }
      consent = std::move(decoded.value());
    }
  }
  Result<std::int64_t> created = reader.i64();
  if (!created) {
    return created.status();
  }
  Result<std::int64_t> updated = reader.i64();
  if (!updated) {
    return updated.status();
  }
  Result<std::uint64_t> revision = decode_counter(reader, limits::kMaxGeneration);
  if (!revision) {
    return revision.status();
  }
  Result<Provenance> provenance = decode_provenance(reader);
  if (!provenance) {
    return provenance.status();
  }
  record.capacity = CapacityUnits(capacity.value());
  record.lease_duration = Duration::from_nanos(lease.value());
  record.terms_digest = terms.value();
  record.state = state.value();
  record.created_at = Timestamp::from_unix_nanos(created.value());
  record.updated_at = Timestamp::from_unix_nanos(updated.value());
  record.revision = Revision(revision.value());
  record.provenance = provenance.value();
  return record;
}

void encode_grant(const GrantRecord& record, ByteWriter& writer) {
  writer.uuid(record.id.uuid());
  writer.uuid(record.contract.uuid());
  writer.digest(record.terms_digest);
  writer.u64(record.coordinator_term.value());
  writer.uuid(record.coordinator.uuid());
  writer.uuid(record.attempt.uuid());
  for (std::size_t i = 0; i < kPartyCount; ++i) {
    writer.uuid(record.incarnations[i].uuid());
    writer.u64(record.generations[i].value());
    writer.u64(record.policies[i].value());
  }
  writer.u64(record.capacity.value());
  writer.i64(record.issued_at.unix_nanos());
  writer.i64(record.valid_until.unix_nanos());
  writer.u8(static_cast<std::uint8_t>(record.state));
  for (std::size_t i = 0; i < kPartyCount; ++i) {
    writer.boolean(record.acknowledged[i]);
    writer.digest(record.enforcement_digest[i]);
  }
  writer.u64(record.revalidate_attempts);
  writer.blob(record.note);
  writer.u64(record.revision.value());
  encode_provenance(record.provenance, writer);
}

Result<GrantRecord> decode_grant(ByteReader& reader) {
  GrantRecord record;
  Result<Uuid> id = reader.uuid();
  if (!id) {
    return id.status();
  }
  Result<Uuid> contract = reader.uuid();
  if (!contract) {
    return contract.status();
  }
  Result<Digest> terms = reader.digest();
  if (!terms) {
    return terms.status();
  }
  Result<std::uint64_t> term = decode_counter(reader, limits::kMaxGeneration);
  if (!term) {
    return term.status();
  }
  Result<Uuid> coordinator = reader.uuid();
  if (!coordinator) {
    return coordinator.status();
  }
  Result<Uuid> attempt = reader.uuid();
  if (!attempt) {
    return attempt.status();
  }
  record.id = GrantId::from_uuid(id.value());
  record.contract = ContractId::from_uuid(contract.value());
  record.terms_digest = terms.value();
  record.coordinator_term = Term(term.value());
  record.coordinator = IncarnationId::from_uuid(coordinator.value());
  record.attempt = AttemptId::from_uuid(attempt.value());

  for (std::size_t i = 0; i < kPartyCount; ++i) {
    Result<Uuid> incarnation = reader.uuid();
    if (!incarnation) {
      return incarnation.status();
    }
    Result<std::uint64_t> generation = decode_counter(reader, limits::kMaxGeneration);
    if (!generation) {
      return generation.status();
    }
    Result<std::uint64_t> policy = decode_counter(reader, limits::kMaxGeneration);
    if (!policy) {
      return policy.status();
    }
    record.incarnations[i] = IncarnationId::from_uuid(incarnation.value());
    record.generations[i] = Generation(generation.value());
    record.policies[i] = PolicyGeneration(policy.value());
  }
  Result<std::uint64_t> capacity = decode_counter(reader, limits::kMaxCapacity);
  if (!capacity) {
    return capacity.status();
  }
  Result<std::int64_t> issued = reader.i64();
  if (!issued) {
    return issued.status();
  }
  Result<std::int64_t> valid_until = reader.i64();
  if (!valid_until) {
    return valid_until.status();
  }
  Result<GrantState> state = decode_enum8<GrantState>(reader, 8);
  if (!state) {
    return state.status();
  }
  for (std::size_t i = 0; i < kPartyCount; ++i) {
    Result<bool> acknowledged = reader.boolean();
    if (!acknowledged) {
      return acknowledged.status();
    }
    Result<Digest> digest = reader.digest();
    if (!digest) {
      return digest.status();
    }
    record.acknowledged[i] = acknowledged.value();
    record.enforcement_digest[i] = digest.value();
  }
  Result<std::uint64_t> attempts = decode_counter(reader, limits::kMaxRevalidateAttempts * 4096);
  if (!attempts) {
    return attempts.status();
  }
  Result<std::string> note = decode_text(reader);
  if (!note) {
    return note.status();
  }
  Result<std::uint64_t> revision = decode_counter(reader, limits::kMaxGeneration);
  if (!revision) {
    return revision.status();
  }
  Result<Provenance> provenance = decode_provenance(reader);
  if (!provenance) {
    return provenance.status();
  }
  record.capacity = CapacityUnits(capacity.value());
  record.issued_at = Timestamp::from_unix_nanos(issued.value());
  record.valid_until = Timestamp::from_unix_nanos(valid_until.value());
  record.state = state.value();
  record.revalidate_attempts = attempts.value();
  record.note = std::move(note.value());
  record.revision = Revision(revision.value());
  record.provenance = provenance.value();
  return record;
}

void encode_reservation(const ReservationRecord& record, ByteWriter& writer) {
  writer.uuid(record.id.uuid());
  writer.uuid(record.grant.uuid());
  writer.blob(record.endpoint.str());
  writer.blob(record.cluster.str());
  writer.u64(record.amount.value());
  writer.boolean(record.released);
  writer.i64(record.created_at.unix_nanos());
  writer.i64(record.released_at.unix_nanos());
  writer.u64(record.revision.value());
  encode_provenance(record.provenance, writer);
}

Result<ReservationRecord> decode_reservation(ByteReader& reader) {
  ReservationRecord record;
  Result<Uuid> id = reader.uuid();
  if (!id) {
    return id.status();
  }
  Result<Uuid> grant = reader.uuid();
  if (!grant) {
    return grant.status();
  }
  Result<EndpointId> endpoint = decode_name<EndpointId>(reader, limits::kMaxNameLength);
  if (!endpoint) {
    return endpoint.status();
  }
  Result<ClusterId> cluster = decode_name<ClusterId>(reader, limits::kMaxNameLength);
  if (!cluster) {
    return cluster.status();
  }
  Result<std::uint64_t> amount = decode_counter(reader, limits::kMaxCapacity);
  if (!amount) {
    return amount.status();
  }
  Result<bool> released = reader.boolean();
  if (!released) {
    return released.status();
  }
  Result<std::int64_t> created = reader.i64();
  if (!created) {
    return created.status();
  }
  Result<std::int64_t> released_at = reader.i64();
  if (!released_at) {
    return released_at.status();
  }
  Result<std::uint64_t> revision = decode_counter(reader, limits::kMaxGeneration);
  if (!revision) {
    return revision.status();
  }
  Result<Provenance> provenance = decode_provenance(reader);
  if (!provenance) {
    return provenance.status();
  }
  record.id = ReservationId::from_uuid(id.value());
  record.grant = GrantId::from_uuid(grant.value());
  record.endpoint = endpoint.value();
  record.cluster = cluster.value();
  record.amount = CapacityUnits(amount.value());
  record.released = released.value();
  record.created_at = Timestamp::from_unix_nanos(created.value());
  record.released_at = Timestamp::from_unix_nanos(released_at.value());
  record.revision = Revision(revision.value());
  record.provenance = provenance.value();
  return record;
}

void encode_audit(const AuditRecord& record, ByteWriter& writer) {
  writer.u64(record.sequence.value());
  writer.i64(record.at.unix_nanos());
  writer.blob(record.actor);
  writer.blob(record.action);
  writer.blob(record.subject);
  writer.u16(static_cast<std::uint16_t>(record.outcome));
  writer.blob(record.detail);
}

Result<AuditRecord> decode_audit(ByteReader& reader) {
  AuditRecord record;
  Result<std::uint64_t> sequence = reader.u64();
  if (!sequence) {
    return sequence.status();
  }
  Result<std::int64_t> at = reader.i64();
  if (!at) {
    return at.status();
  }
  Result<std::string> actor = decode_text(reader);
  if (!actor) {
    return actor.status();
  }
  Result<std::string> action = decode_text(reader);
  if (!action) {
    return action.status();
  }
  Result<std::string> subject = decode_text(reader);
  if (!subject) {
    return subject.status();
  }
  Result<std::uint16_t> outcome = reader.u16();
  if (!outcome) {
    return outcome.status();
  }
  Outcome parsed = Outcome::Internal;
  if (outcome.value() > static_cast<std::uint16_t>(Outcome::Internal)) {
    return invalid("audit outcome is out of range");
  }
  parsed = static_cast<Outcome>(outcome.value());
  Result<std::string> detail = decode_text(reader);
  if (!detail) {
    return detail.status();
  }
  record.sequence = Sequence(sequence.value());
  record.at = Timestamp::from_unix_nanos(at.value());
  record.actor = std::move(actor.value());
  record.action = std::move(action.value());
  record.subject = std::move(subject.value());
  record.outcome = parsed;
  record.detail = std::move(detail.value());
  return record;
}

void encode_registry(const Registry& registry, ByteWriter& writer, bool include_audit) {
  writer.u16(kModelEncodingVersion);
  writer.boolean(include_audit);

  const bool clusters_ok = writer.count(registry.clusters().size());
  (void)clusters_ok;
  for (const auto& entry : registry.clusters()) {
    encode_cluster(entry.second, writer);
  }
  const bool links_ok = writer.count(registry.links().size());
  (void)links_ok;
  for (const auto& entry : registry.links()) {
    encode_link(entry.second, writer);
  }
  const bool paths_ok = writer.count(registry.paths().size());
  (void)paths_ok;
  for (const auto& entry : registry.paths()) {
    encode_path(entry.second, writer);
  }
  const bool policies_ok = writer.count(registry.policies().size());
  (void)policies_ok;
  for (const auto& entry : registry.policies()) {
    encode_policy(entry.second, writer);
  }
  const bool contracts_ok = writer.count(registry.contracts().size());
  (void)contracts_ok;
  for (const auto& entry : registry.contracts()) {
    encode_contract(entry.second, writer);
  }
  const bool grants_ok = writer.count(registry.grants().size());
  (void)grants_ok;
  for (const auto& entry : registry.grants()) {
    encode_grant(entry.second, writer);
  }
  const bool reservations_ok = writer.count(registry.reservations().size());
  (void)reservations_ok;
  for (const auto& entry : registry.reservations()) {
    encode_reservation(entry.second, writer);
  }
  if (include_audit) {
    const bool audit_ok = writer.count(registry.audit().size());
    (void)audit_ok;
    for (const AuditRecord& record : registry.audit()) {
      encode_audit(record, writer);
    }
  }
}

Result<Registry> decode_registry(ByteReader& reader) {
  Result<std::uint16_t> version = reader.u16();
  if (!version) {
    return version.status();
  }
  if (version.value() != kModelEncodingVersion) {
    return Status::make(Outcome::Incompatible, "model encoding version is not supported");
  }
  Result<bool> include_audit = reader.boolean();
  if (!include_audit) {
    return include_audit.status();
  }
  Registry registry;

  Result<std::size_t> cluster_count = reader.count(limits::kMaxClusters);
  if (!cluster_count) {
    return cluster_count.status();
  }
  for (std::size_t i = 0; i < cluster_count.value(); ++i) {
    Result<ClusterRecord> record = decode_cluster(reader);
    if (!record) {
      return record.status();
    }
    const Status status = registry.put_cluster(std::move(record.value()));
    if (!status) {
      return status;
    }
  }
  Result<std::size_t> link_count = reader.count(limits::kMaxEdges);
  if (!link_count) {
    return link_count.status();
  }
  for (std::size_t i = 0; i < link_count.value(); ++i) {
    Result<LinkRecord> record = decode_link(reader);
    if (!record) {
      return record.status();
    }
    const Status status = registry.put_link(std::move(record.value()));
    if (!status) {
      return status;
    }
  }
  Result<std::size_t> path_count = reader.count(limits::kMaxPaths);
  if (!path_count) {
    return path_count.status();
  }
  for (std::size_t i = 0; i < path_count.value(); ++i) {
    Result<PathRecord> record = decode_path(reader);
    if (!record) {
      return record.status();
    }
    const Status status = registry.put_path(std::move(record.value()));
    if (!status) {
      return status;
    }
  }
  Result<std::size_t> policy_count = reader.count(limits::kMaxPolicyRules);
  if (!policy_count) {
    return policy_count.status();
  }
  for (std::size_t i = 0; i < policy_count.value(); ++i) {
    Result<PolicyRule> record = decode_policy(reader);
    if (!record) {
      return record.status();
    }
    const Status status = registry.put_policy(std::move(record.value()));
    if (!status) {
      return status;
    }
  }
  Result<std::size_t> contract_count = reader.count(limits::kMaxContracts);
  if (!contract_count) {
    return contract_count.status();
  }
  for (std::size_t i = 0; i < contract_count.value(); ++i) {
    Result<ContractRecord> record = decode_contract(reader);
    if (!record) {
      return record.status();
    }
    const Status status = registry.put_contract(std::move(record.value()));
    if (!status) {
      return status;
    }
  }
  Result<std::size_t> grant_count = reader.count(limits::kMaxGrants);
  if (!grant_count) {
    return grant_count.status();
  }
  for (std::size_t i = 0; i < grant_count.value(); ++i) {
    Result<GrantRecord> record = decode_grant(reader);
    if (!record) {
      return record.status();
    }
    const Status status = registry.put_grant(std::move(record.value()));
    if (!status) {
      return status;
    }
  }
  Result<std::size_t> reservation_count = reader.count(limits::kMaxReservations);
  if (!reservation_count) {
    return reservation_count.status();
  }
  for (std::size_t i = 0; i < reservation_count.value(); ++i) {
    Result<ReservationRecord> record = decode_reservation(reader);
    if (!record) {
      return record.status();
    }
    const Status status = registry.put_reservation(std::move(record.value()));
    if (!status) {
      return status;
    }
  }
  if (include_audit.value()) {
    Result<std::size_t> audit_count = reader.count(limits::kMaxAuditRecords);
    if (!audit_count) {
      return audit_count.status();
    }
    for (std::size_t i = 0; i < audit_count.value(); ++i) {
      Result<AuditRecord> record = decode_audit(reader);
      if (!record) {
        return record.status();
      }
      const Status status = registry.append_audit(std::move(record.value()));
      if (!status) {
        return status;
      }
    }
  }
  const Status end = reader.expect_end();
  if (!end) {
    return end;
  }
  return registry;
}

}  // namespace icf::model
