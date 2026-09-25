// Inter-Cluster Fabric - model construction helpers shared by the tests.
#pragma once

#include <string>
#include <vector>

#include "icf/core/rng.hpp"
#include "icf/model/policy.hpp"
#include "icf/model/terms.hpp"
#include "icf/runtime/engine.hpp"

namespace icf::test {

struct ClusterFixture {
  model::ClusterRecord cluster;
  EndpointId endpoint;
};

inline model::EndpointRecord endpoint_for(const ClusterId& cluster, const std::string& id, const std::string& scope,
                                          std::uint64_t capacity, PolicyGeneration policy) {
  model::EndpointRecord endpoint;
  endpoint.id = EndpointId::parse(id).value();
  endpoint.cluster = cluster;
  endpoint.scope = ScopeName::parse(scope).value();
  endpoint.capacity = CapacityUnits(capacity);
  endpoint.policy_generation = policy;
  endpoint.state = model::EndpointState::Active;
  endpoint.inter_cluster_allowed = true;
  endpoint.permits_degraded = true;
  endpoint.provenance.source = model::EvidenceSource::AdminConfigured;
  endpoint.provenance.verification = model::VerificationState::Verified;
  return endpoint;
}

inline ClusterFixture make_cluster(const std::string& id, const std::string& domain, const std::string& endpoint_id,
                                   const std::string& scope, std::uint64_t generation, std::uint64_t policy_generation,
                                   Rng& rng, std::uint64_t capacity = 1000) {
  ClusterFixture fixture;
  fixture.cluster.id = ClusterId::parse(id).value();
  fixture.cluster.domain = AuthorityDomainId::parse(domain).value();
  fixture.cluster.incarnation = IncarnationId::random(rng);
  fixture.cluster.generation = Generation(generation);
  fixture.cluster.policy_generation = PolicyGeneration(policy_generation);
  fixture.cluster.state = model::ClusterState::Active;
  fixture.cluster.provenance.source = model::EvidenceSource::AdminConfigured;
  fixture.cluster.provenance.verification = model::VerificationState::Verified;
  fixture.endpoint = EndpointId::parse(endpoint_id).value();
  fixture.cluster.endpoints.push_back(
      endpoint_for(fixture.cluster.id, endpoint_id, scope, capacity, fixture.cluster.policy_generation));
  return fixture;
}

inline model::LinkRecord make_link(const std::string& id, const EndpointId& a, const EndpointId& b,
                                   model::LinkState state = model::LinkState::Up) {
  model::LinkRecord link;
  link.id = EdgeId::parse(id).value();
  link.a = a;
  link.b = b;
  link.kind = model::LinkKind::SyntheticModel;
  link.state = state;
  link.capacity = CapacityUnits(1000);
  link.provenance.source = model::EvidenceSource::AdminConfigured;
  link.provenance.verification = model::VerificationState::Verified;
  return link;
}

inline model::PathRecord make_path(const std::string& id, const EndpointId& a, const EndpointId& b,
                                   const std::vector<std::string>& hops) {
  model::PathRecord path;
  path.id = PathId::parse(id).value();
  path.a = a;
  path.b = b;
  for (const std::string& hop : hops) {
    path.hops.push_back(EdgeId::parse(hop).value());
  }
  path.provenance.source = model::EvidenceSource::DerivedFromTopology;
  path.provenance.verification = model::VerificationState::Verified;
  return path;
}

inline model::PolicyRule allow_rule(const std::string& id, const std::string& owner, const ClusterId& a,
                                    const ClusterId& b, std::uint64_t generation, bool allow = true,
                                    bool allow_degraded = false, std::uint64_t max_capacity = 0) {
  model::PolicyRule rule;
  rule.id = id;
  rule.owner = AuthorityDomainId::parse(owner).value();
  rule.cluster_a = a;
  rule.cluster_b = b;
  rule.generation = PolicyGeneration(generation);
  rule.allow = allow;
  rule.allow_degraded = allow_degraded;
  rule.max_capacity = CapacityUnits(max_capacity);
  rule.provenance.source = model::EvidenceSource::AdminConfigured;
  rule.provenance.verification = model::VerificationState::Verified;
  return rule;
}

struct PairFixture {
  model::Registry registry;
  ClusterFixture source;
  ClusterFixture target;
  Term term = Term(1);
  IncarnationId coordinator;
  Timestamp now = Timestamp::from_unix_nanos(1700000000000000000);
  ContractId contract;
  GrantId grant;
};

// Builds a fully authorized pair: two clusters in two domains, a link, a path, an allow rule
// from each domain, a two-sided contract, and a committed grant.
inline PairFixture make_authorized_pair(Rng& rng, std::uint64_t term_value = 1) {
  PairFixture fixture;
  fixture.term = Term(term_value);
  fixture.coordinator = IncarnationId::random(rng);
  fixture.source = make_cluster("cluster-a", "domain-north", "a-scope", "/a", 5, 2, rng);
  fixture.target = make_cluster("cluster-b", "domain-south", "b-scope", "/b", 9, 3, rng);
  (void)fixture.registry.put_cluster(fixture.source.cluster);
  (void)fixture.registry.put_cluster(fixture.target.cluster);
  (void)fixture.registry.put_link(make_link("edge-ab", fixture.source.endpoint, fixture.target.endpoint));
  (void)fixture.registry.put_path(make_path("path-ab", fixture.source.endpoint, fixture.target.endpoint, {"edge-ab"}));
  (void)fixture.registry.put_policy(allow_rule("allow-north", "domain-north", fixture.source.cluster.id,
                                               fixture.target.cluster.id,
                                               fixture.source.cluster.policy_generation.value(), true, true));
  (void)fixture.registry.put_policy(allow_rule("allow-south", "domain-south", fixture.source.cluster.id,
                                               fixture.target.cluster.id,
                                               fixture.target.cluster.policy_generation.value(), true, true));
  fixture.registry.recompute_path_states();
  return fixture;
}

// Adds the two-sided contract and committed grant to a pair fixture.
inline void authorize_pair(PairFixture& fixture, Rng& rng, bool commit = true,
                           CapacityUnits capacity = CapacityUnits(500)) {
  model::ContractRecord contract;
  contract.id = ContractId::random(rng);
  contract.parties[0] = model::PartyRef{fixture.source.cluster.id, fixture.source.endpoint, fixture.source.cluster.domain};
  contract.parties[1] = model::PartyRef{fixture.target.cluster.id, fixture.target.endpoint, fixture.target.cluster.domain};
  contract.capacity = capacity;
  contract.lease_duration = Duration::from_minutes(5);
  contract.state = model::ContractState::Consented;
  contract.created_at = fixture.now;
  contract.updated_at = fixture.now;
  contract.provenance.source = model::EvidenceSource::DerivedFromTopology;
  contract.provenance.verification = model::VerificationState::Verified;

  model::ContractTerms terms;
  terms.parties = contract.parties;
  terms.capacity = contract.capacity;
  terms.lease_duration = contract.lease_duration;
  terms.incarnations = {fixture.source.cluster.incarnation, fixture.target.cluster.incarnation};
  terms.generations = {fixture.source.cluster.generation, fixture.target.cluster.generation};
  terms.policies = {fixture.source.cluster.policy_generation, fixture.target.cluster.policy_generation};
  terms.proposed_at = fixture.now;
  contract.terms_digest = terms.digest();
  for (std::size_t side = 0; side < model::kPartyCount; ++side) {
    const model::ClusterRecord& cluster = side == 0 ? fixture.source.cluster : fixture.target.cluster;
    model::ConsentRecord consent;
    consent.cluster = cluster.id;
    consent.endpoint = cluster.endpoints[0].id;
    consent.incarnation = cluster.incarnation;
    consent.generation = cluster.generation;
    consent.policy_generation = cluster.policy_generation;
    consent.agent_term = Term(side == 0 ? 3u : 4u);
    consent.terms_digest = contract.terms_digest;
    consent.decision = model::ConsentDecision::Accepted;
    consent.decided_at = fixture.now;
    contract.consents[side] = consent;
  }
  (void)fixture.registry.put_contract(contract);
  fixture.contract = contract.id;

  if (!commit) {
    return;
  }
  model::GrantRecord grant;
  grant.id = GrantId::random(rng);
  grant.contract = contract.id;
  grant.terms_digest = contract.terms_digest;
  grant.coordinator_term = fixture.term;
  grant.coordinator = fixture.coordinator;
  grant.attempt = AttemptId::random(rng);
  grant.incarnations = {fixture.source.cluster.incarnation, fixture.target.cluster.incarnation};
  grant.generations = {fixture.source.cluster.generation, fixture.target.cluster.generation};
  grant.policies = {fixture.source.cluster.policy_generation, fixture.target.cluster.policy_generation};
  grant.capacity = contract.capacity;
  grant.issued_at = fixture.now;
  grant.valid_until = fixture.now.plus(contract.lease_duration);
  grant.state = model::GrantState::Active;
  grant.acknowledged = {true, true};
  grant.provenance.source = model::EvidenceSource::DerivedFromTopology;
  grant.provenance.verification = model::VerificationState::Verified;
  (void)fixture.registry.put_grant(grant);
  fixture.grant = grant.id;
}

inline model::DecisionQuery query_for(const PairFixture& fixture, std::uint64_t capacity = 100) {
  model::DecisionQuery query;
  query.source = fixture.source.endpoint;
  query.target = fixture.target.endpoint;
  query.requested_capacity = CapacityUnits(capacity);
  query.at = fixture.now;
  return query;
}

inline runtime::EngineView view_for(const PairFixture& fixture) {
  runtime::EngineView view;
  view.term = fixture.term;
  view.incarnation = fixture.coordinator;
  view.now = fixture.now;
  return view;
}

}  // namespace icf::test
