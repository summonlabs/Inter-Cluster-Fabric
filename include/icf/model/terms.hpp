// Inter-Cluster Fabric - contract terms.
//
// The terms are what both sides consent to. The digest of the canonical encoding is the only
// thing a consent binds: a consent that names a different digest is a different agreement, no
// matter how similar the words are.
#pragma once

#include <array>

#include "icf/core/bytes.hpp"
#include "icf/model/records.hpp"

namespace icf::model {

struct ContractTerms {
  std::array<PartyRef, kPartyCount> parties;
  CapacityUnits capacity;
  Duration lease_duration;
  std::array<IncarnationId, kPartyCount> incarnations;
  std::array<Generation, kPartyCount> generations;
  std::array<PolicyGeneration, kPartyCount> policies;
  Timestamp proposed_at{};

  [[nodiscard]] Digest digest() const;
  [[nodiscard]] int side_of(const ClusterId& cluster) const noexcept;
  [[nodiscard]] Status validate() const;
};

void encode_terms(const ContractTerms& terms, ByteWriter& writer);
[[nodiscard]] Result<ContractTerms> decode_terms(ByteReader& reader);

}  // namespace icf::model
