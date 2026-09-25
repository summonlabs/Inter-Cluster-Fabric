// Example: evaluate cross-cluster connectivity authority with the runtime library only.
//
// This program builds a model in memory - one cluster pair, one link, one path, one two-sided
// contract, one committed grant - and then asks the decision engine the runtime's core question
// for several scenarios. It is the smallest complete demonstration of the authorization rules,
// and it runs entirely in-process (no sockets, no coordinator).
#include <cstdio>
#include <string>

#include "icf/core/rng.hpp"
#include "icf/core/time.hpp"
#include "icf/model/policy.hpp"
#include "icf/runtime/engine.hpp"

namespace {

icf::model::ClusterRecord make_cluster(const char* id, const char* domain, std::uint64_t generation,
                                       std::uint64_t policy_generation, const icf::IncarnationId& incarnation) {
  icf::model::ClusterRecord cluster;
  cluster.id = icf::ClusterId::parse(id).value();
  cluster.domain = icf::AuthorityDomainId::parse(domain).value();
  cluster.incarnation = incarnation;
  cluster.generation = icf::Generation(generation);
  cluster.policy_generation = icf::PolicyGeneration(policy_generation);
  cluster.state = icf::model::ClusterState::Active;
  cluster.provenance.source = icf::model::EvidenceSource::AdminConfigured;
  cluster.provenance.verification = icf::model::VerificationState::Verified;
  return cluster;
}

icf::model::EndpointRecord make_endpoint(const char* id, const char* cluster, const char* scope, std::uint64_t capacity,
                                         std::uint64_t policy_generation) {
  icf::model::EndpointRecord endpoint;
  endpoint.id = icf::EndpointId::parse(id).value();
  endpoint.cluster = icf::ClusterId::parse(cluster).value();
  endpoint.scope = icf::ScopeName::parse(scope).value();
  endpoint.capacity = icf::CapacityUnits(capacity);
  endpoint.policy_generation = icf::PolicyGeneration(policy_generation);
  endpoint.state = icf::model::EndpointState::Active;
  endpoint.inter_cluster_allowed = true;
  endpoint.permits_degraded = false;
  endpoint.provenance.source = icf::model::EvidenceSource::AdminConfigured;
  endpoint.provenance.verification = icf::model::VerificationState::Verified;
  return endpoint;
}

void report(const char* label, const icf::model::Decision& decision) {
  std::printf("%-34s -> %s (%s)\n", label, icf::to_string(decision.outcome), decision.detail.c_str());
}

}  // namespace

int main() {
  icf::SystemClock clock;
  icf::Rng rng(0x5EED);
  const icf::IncarnationId incarnation_a = icf::IncarnationId::random(rng);
  const icf::IncarnationId incarnation_b = icf::IncarnationId::random(rng);

  icf::model::Registry registry;
  icf::model::ClusterRecord cluster_a = make_cluster("cluster-alpha", "domain-north", 4, 2, incarnation_a);
  cluster_a.endpoints.push_back(make_endpoint("alpha-scope", "cluster-alpha", "/accelerator/a", 1000, 2));
  icf::model::ClusterRecord cluster_b = make_cluster("cluster-beta", "domain-south", 7, 3, incarnation_b);
  cluster_b.endpoints.push_back(make_endpoint("beta-scope", "cluster-beta", "/accelerator/b", 1000, 3));
  (void)registry.put_cluster(cluster_a);
  (void)registry.put_cluster(cluster_b);

  // A link and a path. The link kind is SYNTHETIC here: the example declares topology, it does
  // not drive a transport. The daemons are what exercise a real framed transport.
  icf::model::LinkRecord link;
  link.id = icf::EdgeId::parse("edge-alpha-beta").value();
  link.a = icf::EndpointId::parse("alpha-scope").value();
  link.b = icf::EndpointId::parse("beta-scope").value();
  link.kind = icf::model::LinkKind::SyntheticModel;
  link.state = icf::model::LinkState::Up;
  link.capacity = icf::CapacityUnits(1000);
  link.provenance.source = icf::model::EvidenceSource::AdminConfigured;
  link.provenance.verification = icf::model::VerificationState::Verified;
  (void)registry.put_link(link);

  icf::model::PathRecord path;
  path.id = icf::PathId::parse("path-alpha-beta").value();
  path.a = link.a;
  path.b = link.b;
  path.hops.push_back(link.id);
  path.provenance.source = icf::model::EvidenceSource::DerivedFromTopology;
  path.provenance.verification = icf::model::VerificationState::Verified;
  (void)registry.put_path(path);
  registry.recompute_path_states();

  // Both authority domains must allow the pair: policy is deny-by-default and two-sided.
  for (const char* owner : {"domain-north", "domain-south"}) {
    icf::model::PolicyRule rule;
    rule.id = std::string("allow-") + owner;
    rule.owner = icf::AuthorityDomainId::parse(owner).value();
    rule.cluster_a = cluster_a.id;
    rule.cluster_b = cluster_b.id;
    rule.generation = icf::PolicyGeneration(1);
    rule.allow = true;
    rule.allow_degraded = false;
    rule.provenance.source = icf::model::EvidenceSource::AdminConfigured;
    rule.provenance.verification = icf::model::VerificationState::Verified;
    (void)registry.put_policy(rule);
  }

  const icf::Term term(3);
  const icf::Timestamp now = clock.now();

  icf::model::ContractRecord contract;
  contract.id = icf::ContractId::random(rng);
  contract.parties[0] = icf::model::PartyRef{cluster_a.id, cluster_a.endpoints[0].id, cluster_a.domain};
  contract.parties[1] = icf::model::PartyRef{cluster_b.id, cluster_b.endpoints[0].id, cluster_b.domain};
  contract.capacity = icf::CapacityUnits(500);
  contract.lease_duration = icf::Duration::from_minutes(5);
  contract.state = icf::model::ContractState::Consented;
  contract.created_at = now;
  contract.updated_at = now;
  contract.provenance.source = icf::model::EvidenceSource::DerivedFromTopology;
  contract.provenance.verification = icf::model::VerificationState::Verified;
  for (std::size_t side = 0; side < icf::model::kPartyCount; ++side) {
    const icf::model::ClusterRecord& cluster = side == 0 ? cluster_a : cluster_b;
    contract.consents[side] = icf::model::ConsentRecord{cluster.id,
                                                       cluster.endpoints[0].id,
                                                       cluster.incarnation,
                                                       cluster.generation,
                                                       cluster.policy_generation,
                                                       icf::Term(side == 0 ? 11u : 22u),
                                                       icf::Digest{},
                                                       icf::model::ConsentDecision::Accepted,
                                                       now,
                                                       icf::SessionToken{},
                                                       icf::model::TransportAuthenticity::None,
                                                       "example consent"};
  }
  // Both sides must consent to identical terms: derive one digest and bind both consents to it.
  icf::model::ContractTerms terms;
  terms.parties = contract.parties;
  terms.capacity = contract.capacity;
  terms.lease_duration = contract.lease_duration;
  terms.incarnations = {cluster_a.incarnation, cluster_b.incarnation};
  terms.generations = {cluster_a.generation, cluster_b.generation};
  terms.policies = {cluster_a.policy_generation, cluster_b.policy_generation};
  terms.proposed_at = now;
  contract.terms_digest = terms.digest();
  for (auto& consent : contract.consents) {
    consent->terms_digest = contract.terms_digest;
  }
  (void)registry.put_contract(contract);

  icf::model::GrantRecord grant;
  grant.id = icf::GrantId::random(rng);
  grant.contract = contract.id;
  grant.terms_digest = contract.terms_digest;
  grant.coordinator_term = term;
  grant.coordinator = icf::IncarnationId::random(rng);
  grant.attempt = icf::AttemptId::random(rng);
  grant.incarnations = {cluster_a.incarnation, cluster_b.incarnation};
  grant.generations = {cluster_a.generation, cluster_b.generation};
  grant.policies = {cluster_a.policy_generation, cluster_b.policy_generation};
  grant.capacity = icf::CapacityUnits(400);
  grant.issued_at = now;
  grant.valid_until = now.plus(icf::Duration::from_minutes(5));
  grant.state = icf::model::GrantState::Active;
  grant.acknowledged = {true, true};
  grant.provenance.source = icf::model::EvidenceSource::DerivedFromTopology;
  grant.provenance.verification = icf::model::VerificationState::Verified;
  (void)registry.put_grant(grant);

  icf::runtime::EngineView view;
  view.term = term;
  view.incarnation = grant.coordinator;
  view.now = now;

  icf::model::DecisionQuery query;
  query.source = cluster_a.endpoints[0].id;
  query.target = cluster_b.endpoints[0].id;
  query.requested_capacity = icf::CapacityUnits(100);
  query.at = now;

  report("authorized pair", icf::runtime::decide(registry, query, view));

  icf::model::DecisionQuery over_capacity = query;
  over_capacity.requested_capacity = icf::CapacityUnits(900);
  report("capacity above the grant", icf::runtime::decide(registry, over_capacity, view));

  icf::model::DecisionQuery stale = query;
  stale.expect_source_generation = true;
  stale.source_generation = icf::Generation(3);
  report("caller expects generation 3", icf::runtime::decide(registry, stale, view));

  // A degraded path is a distinct outcome, never a silent success.
  icf::model::LinkRecord degraded = link;
  degraded.state = icf::model::LinkState::Degraded;
  (void)registry.put_link(degraded);
  registry.recompute_path_states();
  report("degraded link", icf::runtime::decide(registry, query, view));

  // Fencing: the far cluster reincarnates, so every dependent grant must be withdrawn.
  const icf::model::FencePlan plan =
      icf::runtime::plan_fence(registry, icf::model::FenceTrigger::ClusterReincarnation, cluster_b.id,
                               icf::IncarnationId::random(rng), cluster_b.incarnation, icf::Generation(8), term);
  std::printf("fence plan for cluster-beta: %zu action(s)\n", plan.actions.size());

  icf::model::ClusterRecord reincarnated = cluster_b;
  reincarnated.incarnation = icf::IncarnationId::random(rng);
  reincarnated.generation = icf::Generation(8);
  (void)registry.put_cluster(reincarnated);
  report("after the peer reincarnated", icf::runtime::decide(registry, query, view));
  return 0;
}
