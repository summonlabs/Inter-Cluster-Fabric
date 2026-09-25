#include "icf/model/terms.hpp"

#include "icf/core/checked.hpp"
#include "icf/core/limits.hpp"

namespace icf::model {

Digest ContractTerms::digest() const {
  ByteWriter writer;
  encode_terms(*this, writer);
  return Sha256::hash(writer.data());
}

int ContractTerms::side_of(const ClusterId& cluster) const noexcept {
  for (std::size_t i = 0; i < parties.size(); ++i) {
    if (parties[i].cluster == cluster) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

Status ContractTerms::validate() const {
  if (parties[0].cluster.empty() || parties[1].cluster.empty()) {
    return invalid("contract terms require two cluster identities");
  }
  if (parties[0].cluster == parties[1].cluster) {
    return invalid("contract terms must join two distinct clusters");
  }
  if (parties[0].endpoint.empty() || parties[1].endpoint.empty()) {
    return invalid("contract terms require two endpoint scopes");
  }
  if (parties[0].domain.empty() || parties[1].domain.empty()) {
    return invalid("contract terms require two authority domains");
  }
  if (capacity.value() > limits::kMaxCapacity) {
    return Status::make(Outcome::Overflow, "contract capacity exceeds the maximum supported value");
  }
  if (lease_duration.is_negative() || static_cast<std::uint64_t>(lease_duration.nanos()) > limits::kMaxDurationNanos) {
    return invalid("contract lease duration is out of range");
  }
  if (parties[0].domain == parties[1].domain) {
    // A single domain cannot provide two-sided consent on its own.
    return Status::make(Outcome::Unsupported,
                        "both endpoints are governed by one authority domain: two-sided consent is not available");
  }
  return Status::ok();
}

void encode_terms(const ContractTerms& terms, ByteWriter& writer) {
  for (const PartyRef& party : terms.parties) {
    writer.blob(party.cluster.str());
    writer.blob(party.endpoint.str());
    writer.blob(party.domain.str());
  }
  writer.u64(terms.capacity.value());
  writer.i64(terms.lease_duration.nanos());
  for (const IncarnationId& incarnation : terms.incarnations) {
    writer.uuid(incarnation.uuid());
  }
  for (const Generation& generation : terms.generations) {
    writer.u64(generation.value());
  }
  for (const PolicyGeneration& policy : terms.policies) {
    writer.u64(policy.value());
  }
  writer.i64(terms.proposed_at.unix_nanos());
}

Result<ContractTerms> decode_terms(ByteReader& reader) {
  ContractTerms terms;
  for (PartyRef& party : terms.parties) {
    Result<std::string> cluster_text = reader.blob(limits::kMaxNameLength);
    if (!cluster_text) {
      return cluster_text.status();
    }
    Result<ClusterId> parsed_cluster = ClusterId::parse(cluster_text.value());
    if (!parsed_cluster) {
      return parsed_cluster.status();
    }
    Result<std::string> endpoint_text = reader.blob(limits::kMaxNameLength);
    if (!endpoint_text) {
      return endpoint_text.status();
    }
    Result<EndpointId> parsed_endpoint = EndpointId::parse(endpoint_text.value());
    if (!parsed_endpoint) {
      return parsed_endpoint.status();
    }
    Result<std::string> domain_text = reader.blob(limits::kMaxNameLength);
    if (!domain_text) {
      return domain_text.status();
    }
    Result<AuthorityDomainId> parsed_domain = AuthorityDomainId::parse(domain_text.value());
    if (!parsed_domain) {
      return parsed_domain.status();
    }
    party.cluster = parsed_cluster.value();
    party.endpoint = parsed_endpoint.value();
    party.domain = parsed_domain.value();
  }
  Result<std::uint64_t> capacity = reader.u64();
  if (!capacity) {
    return capacity.status();
  }
  if (capacity.value() > limits::kMaxCapacity) {
    return Status::make(Outcome::Overflow, "contract capacity exceeds the maximum supported value");
  }
  Result<std::int64_t> lease = reader.i64();
  if (!lease) {
    return lease.status();
  }
  if (lease.value() < 0 || static_cast<std::uint64_t>(lease.value()) > limits::kMaxDurationNanos) {
    return invalid("contract lease duration is out of range");
  }
  terms.capacity = CapacityUnits(capacity.value());
  terms.lease_duration = Duration::from_nanos(lease.value());
  for (IncarnationId& incarnation : terms.incarnations) {
    Result<Uuid> uuid = reader.uuid();
    if (!uuid) {
      return uuid.status();
    }
    incarnation = IncarnationId::from_uuid(uuid.value());
  }
  for (Generation& generation : terms.generations) {
    Result<std::uint64_t> value = reader.u64();
    if (!value) {
      return value.status();
    }
    if (value.value() > limits::kMaxGeneration) {
      return Status::make(Outcome::Overflow, "generation exceeds the maximum supported value");
    }
    generation = Generation(value.value());
  }
  for (PolicyGeneration& policy : terms.policies) {
    Result<std::uint64_t> value = reader.u64();
    if (!value) {
      return value.status();
    }
    if (value.value() > limits::kMaxGeneration) {
      return Status::make(Outcome::Overflow, "policy generation exceeds the maximum supported value");
    }
    policy = PolicyGeneration(value.value());
  }
  Result<std::int64_t> proposed = reader.i64();
  if (!proposed) {
    return proposed.status();
  }
  terms.proposed_at = Timestamp::from_unix_nanos(proposed.value());
  return terms;
}

}  // namespace icf::model
