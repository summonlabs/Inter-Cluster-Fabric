#include "icf/store/mutation.hpp"

#include "icf/core/limits.hpp"

namespace icf::store {
namespace {

}  // namespace

const char* to_string(MutationKind kind) noexcept {
  switch (kind) {
    case MutationKind::Invalid:
      return "INVALID";
    case MutationKind::ClusterPut:
      return "CLUSTER_PUT";
    case MutationKind::ClusterErase:
      return "CLUSTER_ERASE";
    case MutationKind::LinkPut:
      return "LINK_PUT";
    case MutationKind::LinkErase:
      return "LINK_ERASE";
    case MutationKind::PathPut:
      return "PATH_PUT";
    case MutationKind::PathErase:
      return "PATH_ERASE";
    case MutationKind::PolicyPut:
      return "POLICY_PUT";
    case MutationKind::PolicyErase:
      return "POLICY_ERASE";
    case MutationKind::ContractPut:
      return "CONTRACT_PUT";
    case MutationKind::ContractErase:
      return "CONTRACT_ERASE";
    case MutationKind::GrantPut:
      return "GRANT_PUT";
    case MutationKind::GrantErase:
      return "GRANT_ERASE";
    case MutationKind::ReservationPut:
      return "RESERVATION_PUT";
    case MutationKind::AuditAppend:
      return "AUDIT_APPEND";
    case MutationKind::MetaSet:
      return "META_SET";
  }
  return "INVALID";
}

bool mutation_kind_known(MutationKind kind) noexcept {
  return kind != MutationKind::Invalid && kind <= MutationKind::MetaSet;
}

void encode_mutation(const Mutation& mutation, ByteWriter& writer) {
  writer.u16(static_cast<std::uint16_t>(mutation.kind));
  switch (mutation.kind) {
    case MutationKind::ClusterPut:
    case MutationKind::ClusterErase:
      model::encode_cluster(mutation.cluster, writer);
      break;
    case MutationKind::LinkPut:
    case MutationKind::LinkErase:
      model::encode_link(mutation.link, writer);
      break;
    case MutationKind::PathPut:
    case MutationKind::PathErase:
      model::encode_path(mutation.path, writer);
      break;
    case MutationKind::PolicyPut:
    case MutationKind::PolicyErase:
      model::encode_policy(mutation.policy, writer);
      break;
    case MutationKind::ContractPut:
    case MutationKind::ContractErase:
      model::encode_contract(mutation.contract, writer);
      break;
    case MutationKind::GrantPut:
    case MutationKind::GrantErase:
      model::encode_grant(mutation.grant, writer);
      break;
    case MutationKind::ReservationPut:
      model::encode_reservation(mutation.reservation, writer);
      break;
    case MutationKind::AuditAppend:
      model::encode_audit(mutation.audit, writer);
      break;
    case MutationKind::MetaSet:
      writer.u64(mutation.meta_term.value());
      writer.uuid(mutation.meta_incarnation.uuid());
      break;
    case MutationKind::Invalid:
      break;
  }
}

Result<Mutation> decode_mutation(ByteReader& reader) {
  Mutation mutation;
  Result<std::uint16_t> raw_kind = reader.u16();
  if (!raw_kind) {
    return raw_kind.status();
  }
  mutation.kind = static_cast<MutationKind>(raw_kind.value());
  if (!mutation_kind_known(mutation.kind)) {
    return invalid("mutation kind is not recognised");
  }
  switch (mutation.kind) {
    case MutationKind::ClusterPut:
    case MutationKind::ClusterErase: {
      Result<model::ClusterRecord> record = model::decode_cluster(reader);
      if (!record) {
        return record.status();
      }
      mutation.cluster = std::move(record.value());
      break;
    }
    case MutationKind::LinkPut:
    case MutationKind::LinkErase: {
      Result<model::LinkRecord> record = model::decode_link(reader);
      if (!record) {
        return record.status();
      }
      mutation.link = std::move(record.value());
      break;
    }
    case MutationKind::PathPut:
    case MutationKind::PathErase: {
      Result<model::PathRecord> record = model::decode_path(reader);
      if (!record) {
        return record.status();
      }
      mutation.path = std::move(record.value());
      break;
    }
    case MutationKind::PolicyPut:
    case MutationKind::PolicyErase: {
      Result<model::PolicyRule> record = model::decode_policy(reader);
      if (!record) {
        return record.status();
      }
      mutation.policy = std::move(record.value());
      break;
    }
    case MutationKind::ContractPut:
    case MutationKind::ContractErase: {
      Result<model::ContractRecord> record = model::decode_contract(reader);
      if (!record) {
        return record.status();
      }
      mutation.contract = std::move(record.value());
      break;
    }
    case MutationKind::GrantPut:
    case MutationKind::GrantErase: {
      Result<model::GrantRecord> record = model::decode_grant(reader);
      if (!record) {
        return record.status();
      }
      mutation.grant = std::move(record.value());
      break;
    }
    case MutationKind::ReservationPut: {
      Result<model::ReservationRecord> record = model::decode_reservation(reader);
      if (!record) {
        return record.status();
      }
      mutation.reservation = std::move(record.value());
      break;
    }
    case MutationKind::AuditAppend: {
      Result<model::AuditRecord> record = model::decode_audit(reader);
      if (!record) {
        return record.status();
      }
      mutation.audit = std::move(record.value());
      break;
    }
    case MutationKind::MetaSet: {
      Result<std::uint64_t> term = reader.u64();
      if (!term) {
        return term.status();
      }
      if (term.value() > limits::kMaxGeneration) {
        return Status::make(Outcome::Overflow, "term exceeds the maximum supported value");
      }
      mutation.meta_term = Term(term.value());
      Result<Uuid> incarnation = reader.uuid();
      if (!incarnation) {
        return incarnation.status();
      }
      mutation.meta_incarnation = IncarnationId::from_uuid(incarnation.value());
      break;
    }
    case MutationKind::Invalid:
      return invalid("mutation kind is not recognised");
  }
  return mutation;
}

Status validate_mutation(const model::Registry& registry, const Mutation& mutation) {
  switch (mutation.kind) {
    case MutationKind::ClusterPut:
      if (mutation.cluster.id.empty()) {
        return invalid("cluster mutation requires an identity");
      }
      if (registry.find_cluster(mutation.cluster.id) == nullptr && registry.clusters().size() >= limits::kMaxClusters) {
        return Status::make(Outcome::CapacityExceeded, "cluster registry is full");
      }
      if (mutation.cluster.endpoints.size() > limits::kMaxEndpointsPerCluster) {
        return Status::make(Outcome::CapacityExceeded, "cluster declares too many endpoints");
      }
      return Status::ok();
    case MutationKind::ClusterErase:
      return mutation.cluster.id.empty() ? invalid("cluster erase requires an identity") : Status::ok();
    case MutationKind::LinkPut:
      if (mutation.link.id.empty() || mutation.link.a.empty() || mutation.link.b.empty()) {
        return invalid("link mutation requires an identity and two endpoints");
      }
      if (mutation.link.reserved > mutation.link.capacity) {
        return Status::make(Outcome::CapacityExceeded, "link reservations exceed declared capacity");
      }
      return Status::ok();
    case MutationKind::LinkErase:
      return mutation.link.id.empty() ? invalid("link erase requires an identity") : Status::ok();
    case MutationKind::PathPut:
      if (mutation.path.id.empty() || mutation.path.hops.empty()) {
        return invalid("path mutation requires an identity and at least one hop");
      }
      if (mutation.path.hops.size() > limits::kMaxPathHops) {
        return Status::make(Outcome::CapacityExceeded, "path declares too many hops");
      }
      return Status::ok();
    case MutationKind::PathErase:
      return mutation.path.id.empty() ? invalid("path erase requires an identity") : Status::ok();
    case MutationKind::PolicyPut:
      return mutation.policy.id.empty() ? invalid("policy mutation requires an identity") : Status::ok();
    case MutationKind::PolicyErase:
      return mutation.policy.id.empty() ? invalid("policy erase requires an identity") : Status::ok();
    case MutationKind::ContractPut:
      return mutation.contract.id.is_nil() ? invalid("contract mutation requires an identity") : Status::ok();
    case MutationKind::ContractErase:
      return mutation.contract.id.is_nil() ? invalid("contract erase requires an identity") : Status::ok();
    case MutationKind::GrantPut:
      if (mutation.grant.id.is_nil()) {
        return invalid("grant mutation requires an identity");
      }
      if (registry.find_contract(mutation.grant.contract) == nullptr) {
        return invalid("grant mutation references an unknown contract");
      }
      return Status::ok();
    case MutationKind::GrantErase:
      return mutation.grant.id.is_nil() ? invalid("grant erase requires an identity") : Status::ok();
    case MutationKind::ReservationPut:
      if (mutation.reservation.id.is_nil()) {
        return invalid("reservation mutation requires an identity");
      }
      if (registry.find_grant(mutation.reservation.grant) == nullptr) {
        return invalid("reservation mutation references an unknown grant");
      }
      return Status::ok();
    case MutationKind::AuditAppend:
      return Status::ok();
    case MutationKind::MetaSet:
      return Status::ok();
    case MutationKind::Invalid:
      return invalid("mutation kind is not recognised");
  }
  return invalid("mutation kind is not recognised");
}

Status apply_mutation(model::Registry& registry, const Mutation& mutation) {
  const Status validation = validate_mutation(registry, mutation);
  if (!validation) {
    return validation;
  }
  switch (mutation.kind) {
    case MutationKind::ClusterPut:
      return registry.put_cluster(mutation.cluster);
    case MutationKind::ClusterErase:
      return registry.erase_cluster(mutation.cluster.id);
    case MutationKind::LinkPut:
      return registry.put_link(mutation.link);
    case MutationKind::LinkErase:
      return registry.erase_link(mutation.link.id);
    case MutationKind::PathPut:
      return registry.put_path(mutation.path);
    case MutationKind::PathErase:
      return registry.erase_path(mutation.path.id);
    case MutationKind::PolicyPut:
      return registry.put_policy(mutation.policy);
    case MutationKind::PolicyErase:
      return registry.erase_policy(mutation.policy.id);
    case MutationKind::ContractPut:
      return registry.put_contract(mutation.contract);
    case MutationKind::ContractErase:
      return registry.erase_contract(mutation.contract.id);
    case MutationKind::GrantPut:
      return registry.put_grant(mutation.grant);
    case MutationKind::GrantErase:
      return registry.erase_grant(mutation.grant.id);
    case MutationKind::ReservationPut:
      return registry.put_reservation(mutation.reservation);
    case MutationKind::AuditAppend:
      return registry.append_audit(mutation.audit);
    case MutationKind::MetaSet:
      return Status::ok();
    case MutationKind::Invalid:
      return invalid("mutation kind is not recognised");
  }
  return invalid("mutation kind is not recognised");
}

}  // namespace icf::store
