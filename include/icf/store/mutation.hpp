// Inter-Cluster Fabric - persisted state mutations.
//
// The coordinator and the cluster agent each persist their authoritative state as a sequence of
// mutations over a well-defined initial state. Recovery replays those mutations with the same
// function the live path uses, so a recovered state is exactly the state the log describes.
#pragma once

#include <cstdint>
#include <string>

#include "icf/model/registry.hpp"

namespace icf::store {

enum class MutationKind : std::uint16_t {
  Invalid = 0,
  ClusterPut = 1,
  ClusterErase = 2,
  LinkPut = 3,
  LinkErase = 4,
  PathPut = 5,
  PathErase = 6,
  PolicyPut = 7,
  PolicyErase = 8,
  ContractPut = 9,
  ContractErase = 10,
  GrantPut = 11,
  GrantErase = 12,
  ReservationPut = 13,
  AuditAppend = 14,
  MetaSet = 15,
};

[[nodiscard]] const char* to_string(MutationKind kind) noexcept;
[[nodiscard]] bool mutation_kind_known(MutationKind kind) noexcept;

struct StoreMeta {
  Term term;
  IncarnationId incarnation;
  Revision revision;
  Sequence sequence;
  Timestamp written_at{};
  std::uint64_t truncations = 0;
  Digest state_digest;
};

struct Mutation {
  MutationKind kind = MutationKind::Invalid;
  model::ClusterRecord cluster;
  model::LinkRecord link;
  model::PathRecord path;
  model::PolicyRule policy;
  model::ContractRecord contract;
  model::GrantRecord grant;
  model::ReservationRecord reservation;
  model::AuditRecord audit;
  Term meta_term;
  IncarnationId meta_incarnation;
  std::string meta_note;
};

void encode_mutation(const Mutation& mutation, ByteWriter& writer);
[[nodiscard]] Result<Mutation> decode_mutation(ByteReader& reader);

// Both functions are pure with respect to the mutation: validate() changes nothing and
// apply() leaves the registry untouched when it returns a negative status.
[[nodiscard]] Status validate_mutation(const model::Registry& registry, const Mutation& mutation);
[[nodiscard]] Status apply_mutation(model::Registry& registry, const Mutation& mutation);

}  // namespace icf::store
