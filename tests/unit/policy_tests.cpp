#include <string>

#include "harness.hpp"
#include "icf/model/policy.hpp"
#include "model_builder.hpp"

using namespace icf;
using namespace icf::test;

ICF_TEST(policy, requires_an_allow_rule_from_every_domain) {
  Rng rng(21);
  PairFixture fixture = make_authorized_pair(rng);
  fixture.registry.policies().clear();
  const model::PolicyEvaluation none = model::evaluate_policy(fixture.registry, fixture.source.cluster,
                                                              fixture.target.cluster, fixture.source.endpoint,
                                                              fixture.target.endpoint);
  ICF_EXPECT_EQ(model::PolicyDecision::MissingAllowRule, none.decision);
  ICF_EXPECT_EQ(static_cast<std::size_t>(2), none.missing_domains.size());

  (void)fixture.registry.put_policy(allow_rule("north-only", "domain-north", fixture.source.cluster.id,
                                               fixture.target.cluster.id,
                                               fixture.source.cluster.policy_generation.value(), true, true));
  const model::PolicyEvaluation one_sided = model::evaluate_policy(
      fixture.registry, fixture.source.cluster, fixture.target.cluster, fixture.source.endpoint, fixture.target.endpoint);
  ICF_EXPECT_EQ(model::PolicyDecision::MissingAllowRule, one_sided.decision);
  ICF_EXPECT_EQ(static_cast<std::size_t>(1), one_sided.missing_domains.size());
  ICF_EXPECT_EQ(std::string("domain-south"), one_sided.missing_domains.front().str());

  (void)fixture.registry.put_policy(allow_rule("south-only", "domain-south", fixture.source.cluster.id,
                                               fixture.target.cluster.id,
                                               fixture.target.cluster.policy_generation.value(), true, false));
  const model::PolicyEvaluation both = model::evaluate_policy(
      fixture.registry, fixture.source.cluster, fixture.target.cluster, fixture.source.endpoint, fixture.target.endpoint);
  ICF_EXPECT_EQ(model::PolicyDecision::Allowed, both.decision);
  ICF_EXPECT_EQ(static_cast<std::size_t>(2), both.rule_ids.size());
  // Degraded permission is the conjunction of both domains' rules: one domain saying "no
  // degraded" is enough to withdraw it for the pair.
  ICF_EXPECT_FALSE(both.allow_degraded);
}

ICF_TEST(policy, refuse_wins_over_allow) {
  Rng rng(22);
  PairFixture fixture = make_authorized_pair(rng);
  (void)fixture.registry.put_policy(allow_rule("refuse-south", "domain-south", fixture.source.cluster.id,
                                               fixture.target.cluster.id,
                                               fixture.target.cluster.policy_generation.value(), false));
  const model::PolicyEvaluation evaluation = model::evaluate_policy(
      fixture.registry, fixture.source.cluster, fixture.target.cluster, fixture.source.endpoint, fixture.target.endpoint);
  ICF_EXPECT_EQ(model::PolicyDecision::RefusedExplicitly, evaluation.decision);
  ICF_EXPECT_EQ(static_cast<std::size_t>(1), evaluation.refusing_domains.size());
}

ICF_TEST(policy, stale_generation_is_not_a_silent_fallback) {
  Rng rng(23);
  PairFixture fixture = make_authorized_pair(rng);
  fixture.registry.policies().clear();
  // Rules bound to an older policy generation of the source cluster.
  (void)fixture.registry.put_policy(allow_rule("old-north", "domain-north", fixture.source.cluster.id,
                                               fixture.target.cluster.id, fixture.source.cluster.policy_generation.value()));
  (void)fixture.registry.put_policy(allow_rule("old-south", "domain-south", fixture.source.cluster.id,
                                               fixture.target.cluster.id, fixture.source.cluster.policy_generation.value()));
  model::ClusterRecord bumped = fixture.source.cluster;
  bumped.policy_generation = PolicyGeneration(9);
  (void)fixture.registry.put_cluster(bumped);
  const model::PolicyEvaluation evaluation = model::evaluate_policy(
      fixture.registry, *fixture.registry.find_cluster(bumped.id), fixture.target.cluster, fixture.source.endpoint,
      fixture.target.endpoint);
  ICF_EXPECT_EQ(model::PolicyDecision::StaleGeneration, evaluation.decision);
}

ICF_TEST(policy, wildcards_and_endpoint_scoping) {
  Rng rng(24);
  PairFixture fixture = make_authorized_pair(rng);
  fixture.registry.policies().clear();
  for (const char* domain : {"domain-north", "domain-south"}) {
    model::PolicyRule rule =
        allow_rule(std::string("wildcard-") + domain, domain, ClusterId{}, ClusterId{},
                   std::string(domain) == "domain-north" ? fixture.source.cluster.policy_generation.value()
                                                         : fixture.target.cluster.policy_generation.value());
    rule.endpoint_a = fixture.source.endpoint;
    rule.endpoint_b = fixture.target.endpoint;
    (void)fixture.registry.put_policy(rule);
  }
  const model::PolicyEvaluation matched = model::evaluate_policy(
      fixture.registry, fixture.source.cluster, fixture.target.cluster, fixture.source.endpoint, fixture.target.endpoint);
  ICF_EXPECT_EQ(model::PolicyDecision::Allowed, matched.decision);

  const model::PolicyEvaluation other_endpoint = model::evaluate_policy(
      fixture.registry, fixture.source.cluster, fixture.target.cluster, EndpointId::parse("different").value(),
      fixture.target.endpoint);
  ICF_EXPECT_EQ(model::PolicyDecision::MissingAllowRule, other_endpoint.decision);
}

ICF_TEST(policy, degraded_and_capacity_are_intersected) {
  Rng rng(25);
  PairFixture fixture = make_authorized_pair(rng);
  fixture.registry.policies().clear();
  model::PolicyRule north =
      allow_rule("north", "domain-north", fixture.source.cluster.id, fixture.target.cluster.id,
                 fixture.source.cluster.policy_generation.value(), true, true, 900);
  model::PolicyRule south =
      allow_rule("south", "domain-south", fixture.source.cluster.id, fixture.target.cluster.id,
                 fixture.target.cluster.policy_generation.value(), true, false, 400);
  (void)fixture.registry.put_policy(north);
  (void)fixture.registry.put_policy(south);
  const model::PolicyEvaluation evaluation = model::evaluate_policy(
      fixture.registry, fixture.source.cluster, fixture.target.cluster, fixture.source.endpoint, fixture.target.endpoint);
  ICF_EXPECT_EQ(model::PolicyDecision::Allowed, evaluation.decision);
  ICF_EXPECT_FALSE(evaluation.allow_degraded);
  ICF_EXPECT_EQ(400ull, evaluation.max_capacity.value());
}

ICF_TEST(policy, rules_from_unrelated_domains_do_not_apply) {
  Rng rng(26);
  PairFixture fixture = make_authorized_pair(rng);
  fixture.registry.policies().clear();
  (void)fixture.registry.put_policy(allow_rule("other", "domain-east", fixture.source.cluster.id,
                                               fixture.target.cluster.id, fixture.source.cluster.policy_generation.value()));
  const model::PolicyEvaluation evaluation = model::evaluate_policy(
      fixture.registry, fixture.source.cluster, fixture.target.cluster, fixture.source.endpoint, fixture.target.endpoint);
  ICF_EXPECT_EQ(model::PolicyDecision::MissingAllowRule, evaluation.decision);
}
