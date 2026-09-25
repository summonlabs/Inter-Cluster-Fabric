// Downstream consumer: exercises the installed Inter-Cluster Fabric package.
//
// It links only against icf::icf from the install prefix, builds a two-domain model, and expects
// the decision engine to authorize the pair. A non-zero exit code means the installed package
// does not behave as documented.
#include <cstdio>
#include <string>

#include "icf/core/rng.hpp"
#include "icf/model/policy.hpp"
#include "icf/model/terms.hpp"
#include "icf/runtime/engine.hpp"
#include "icf/version_api.hpp"

namespace {

int failures = 0;

void expect(bool condition, const char* what) {
  if (!condition) {
    std::fprintf(stderr, "consumer: FAILED: %s\n", what);
    ++failures;
  }
}

icf::model::ClusterRecord cluster_with_endpoint(const char* cluster_id, const char* domain, const char* endpoint_id,
                                                std::uint64_t generation, std::uint64_t policy_generation,
                                                const icf::IncarnationId& incarnation) {
  icf::model::ClusterRecord cluster;
  cluster.id = icf::ClusterId::parse(cluster_id).value();
  cluster.domain = icf::AuthorityDomainId::parse(domain).value();
  cluster.incarnation = incarnation;
  cluster.generation = icf::Generation(generation);
  cluster.policy_generation = icf::PolicyGeneration(policy_generation);
  cluster.state = icf::model::ClusterState::Active;
  cluster.provenance.source = icf::model::EvidenceSource::AdminConfigured;
  cluster.provenance.verification = icf::model::VerificationState::Verified;
  icf::model::EndpointRecord endpoint;
  endpoint.id = icf::EndpointId::parse(endpoint_id).value();
  endpoint.cluster = cluster.id;
  endpoint.scope = icf::ScopeName::parse(std::string("/") + endpoint_id).value();
  endpoint.capacity = icf::CapacityUnits(1000);
  endpoint.policy_generation = cluster.policy_generation;
  endpoint.state = icf::model::EndpointState::Active;
  endpoint.inter_cluster_allowed = true;
  endpoint.permits_degraded = false;
  endpoint.provenance.source = icf::model::EvidenceSource::AdminConfigured;
  endpoint.provenance.verification = icf::model::VerificationState::Verified;
  cluster.endpoints.push_back(endpoint);
  return cluster;
}

}  // namespace

int main() {
  std::printf("consumer: linked against Inter-Cluster Fabric %s (protocol %u..%u)\n", icf::version_string(),
              static_cast<unsigned>(icf::protocol_version_min()), static_cast<unsigned>(icf::protocol_version_max()));

  icf::Rng rng(20260101);
  const icf::IncarnationId incarnation_a = icf::IncarnationId::random(rng);
  const icf::IncarnationId incarnation_b = icf::IncarnationId::random(rng);
  icf::model::Registry registry;
  const icf::model::ClusterRecord cluster_a =
      cluster_with_endpoint("downstream-a", "domain-north", "downstream-a-scope", 3, 1, incarnation_a);
  const icf::model::ClusterRecord cluster_b =
      cluster_with_endpoint("downstream-b", "domain-south", "downstream-b-scope", 4, 1, incarnation_b);
  expect(registry.put_cluster(cluster_a).is_ok(), "cluster a registers");
  expect(registry.put_cluster(cluster_b).is_ok(), "cluster b registers");

  icf::model::LinkRecord link;
  link.id = icf::EdgeId::parse("downstream-edge").value();
  link.a = cluster_a.endpoints[0].id;
  link.b = cluster_b.endpoints[0].id;
  link.kind = icf::model::LinkKind::LoopbackTcp;
  link.state = icf::model::LinkState::Up;
  link.capacity = icf::CapacityUnits(1000);
  link.provenance.source = icf::model::EvidenceSource::AdminConfigured;
  link.provenance.verification = icf::model::VerificationState::Verified;
  expect(registry.put_link(link).is_ok(), "link registers");
  icf::model::PathRecord path;
  path.id = icf::PathId::parse("downstream-path").value();
  path.a = link.a;
  path.b = link.b;
  path.hops.push_back(link.id);
  path.provenance.source = icf::model::EvidenceSource::DerivedFromTopology;
  path.provenance.verification = icf::model::VerificationState::Verified;
  expect(registry.put_path(path).is_ok(), "path registers");
  registry.recompute_path_states();

  for (const char* domain : {"domain-north", "domain-south"}) {
    icf::model::PolicyRule rule;
    rule.id = std::string("downstream-allow-") + domain;
    rule.owner = icf::AuthorityDomainId::parse(domain).value();
    rule.cluster_a = cluster_a.id;
    rule.cluster_b = cluster_b.id;
    rule.generation = icf::PolicyGeneration(1);
    rule.allow = true;
    rule.allow_degraded = false;
    rule.provenance.source = icf::model::EvidenceSource::AdminConfigured;
    rule.provenance.verification = icf::model::VerificationState::Verified;
    expect(registry.put_policy(rule).is_ok(), "policy rule registers");
  }

  const icf::Term term(7);
  const icf::IncarnationId coordinator = icf::IncarnationId::random(rng);
  const icf::Timestamp now = icf::Timestamp::from_unix_nanos(1800000000000000000);

  icf::model::ContractRecord contract;
  contract.id = icf::ContractId::random(rng);
  contract.parties[0] = icf::model::PartyRef{cluster_a.id, cluster_a.endpoints[0].id, cluster_a.domain};
  contract.parties[1] = icf::model::PartyRef{cluster_b.id, cluster_b.endpoints[0].id, cluster_b.domain};
  contract.capacity = icf::CapacityUnits(100);
  contract.lease_duration = icf::Duration::from_minutes(1);
  contract.state = icf::model::ContractState::Consented;
  contract.created_at = now;
  contract.updated_at = now;
  contract.provenance.source = icf::model::EvidenceSource::DerivedFromTopology;
  contract.provenance.verification = icf::model::VerificationState::Verified;
  icf::model::ContractTerms terms;
  terms.parties = contract.parties;
  terms.capacity = contract.capacity;
  terms.lease_duration = contract.lease_duration;
  terms.incarnations = {cluster_a.incarnation, cluster_b.incarnation};
  terms.generations = {cluster_a.generation, cluster_b.generation};
  terms.policies = {cluster_a.policy_generation, cluster_b.policy_generation};
  terms.proposed_at = now;
  contract.terms_digest = terms.digest();
  for (std::size_t side = 0; side < icf::model::kPartyCount; ++side) {
    const icf::model::ClusterRecord& cluster = side == 0 ? cluster_a : cluster_b;
    icf::model::ConsentRecord consent;
    consent.cluster = cluster.id;
    consent.endpoint = cluster.endpoints[0].id;
    consent.incarnation = cluster.incarnation;
    consent.generation = cluster.generation;
    consent.policy_generation = cluster.policy_generation;
    consent.agent_term = icf::Term(side == 0 ? 1u : 2u);
    consent.terms_digest = contract.terms_digest;
    consent.decision = icf::model::ConsentDecision::Accepted;
    consent.decided_at = now;
    contract.consents[side] = consent;
  }
  expect(registry.put_contract(contract).is_ok(), "contract registers");

  icf::model::GrantRecord grant;
  grant.id = icf::GrantId::random(rng);
  grant.contract = contract.id;
  grant.terms_digest = contract.terms_digest;
  grant.coordinator_term = term;
  grant.coordinator = coordinator;
  grant.attempt = icf::AttemptId::random(rng);
  grant.incarnations = {cluster_a.incarnation, cluster_b.incarnation};
  grant.generations = {cluster_a.generation, cluster_b.generation};
  grant.policies = {cluster_a.policy_generation, cluster_b.policy_generation};
  grant.capacity = icf::CapacityUnits(100);
  grant.issued_at = now;
  grant.valid_until = now.plus(icf::Duration::from_minutes(1));
  grant.state = icf::model::GrantState::Active;
  grant.acknowledged = {true, true};
  grant.provenance.source = icf::model::EvidenceSource::DerivedFromTopology;
  grant.provenance.verification = icf::model::VerificationState::Verified;
  expect(registry.put_grant(grant).is_ok(), "grant registers");

  icf::runtime::EngineView view;
  view.term = term;
  view.incarnation = coordinator;
  view.now = now;
  icf::model::DecisionQuery query;
  query.source = cluster_a.endpoints[0].id;
  query.target = cluster_b.endpoints[0].id;
  query.requested_capacity = icf::CapacityUnits(10);
  query.at = now;

  const icf::model::Decision decision = icf::runtime::decide(registry, query, view);
  std::printf("consumer: decision outcome=%s detail=%s\n", icf::to_string(decision.outcome), decision.detail.c_str());
  expect(decision.outcome == icf::Outcome::Ok, "the pair is authorized");
  expect(decision.grant == grant.id, "the decision names the committed grant");
  expect(decision.authorities[0].str() == "domain-north", "the first authority is reported");
  expect(decision.authorities[1].str() == "domain-south", "the second authority is reported");

  if (failures != 0) {
    std::fprintf(stderr, "consumer: %d check(s) failed\n", failures);
    return 1;
  }
  std::printf("consumer: all checks passed\n");
  return 0;
}
