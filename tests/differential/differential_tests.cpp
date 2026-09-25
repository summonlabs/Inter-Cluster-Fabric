// Differential testing: the decision engine against an independent reference model.
//
// Both implementations are run over the same randomly generated registries; the engine's
// authorized/not-authorized answer and the degraded flag must agree with the reference for every
// state, including the states where the answer is "not authorized for a different reason".
#include <string>

#include "harness.hpp"
#include "icf/runtime/engine.hpp"
#include "model_builder.hpp"
#include "reference_model.hpp"

using namespace icf;
using namespace icf::test;

namespace {

model::Registry random_registry(Rng& rng, PairFixture& fixture, bool authorize) {
  fixture = PairFixture{};
  fixture.term = Term(1 + rng.below(100));
  fixture.coordinator = IncarnationId::random(rng);
  fixture.now = Timestamp::from_unix_nanos(1700000000000000000);
  fixture.source = make_cluster("alpha", "north", "alpha-e", "/alpha", 1 + rng.below(50), 1 + rng.below(5), rng, 1000);
  fixture.target = make_cluster("beta", "south", "beta-e", "/beta", 1 + rng.below(50), 1 + rng.below(5), rng, 1000);
  const bool source_active = rng.below(6) != 0;
  const bool target_active = rng.below(6) != 0;
  fixture.source.cluster.state = source_active ? model::ClusterState::Active : model::ClusterState::Unknown;
  fixture.target.cluster.state = target_active ? model::ClusterState::Active : model::ClusterState::Unknown;
  fixture.source.cluster.endpoints[0].permits_degraded = rng.below(2) == 0;
  fixture.target.cluster.endpoints[0].permits_degraded = rng.below(2) == 0;
  fixture.source.cluster.consent_withdrawn = rng.below(12) == 0;
  fixture.target.cluster.generation_conflict = rng.below(12) == 0;
  (void)fixture.registry.put_cluster(fixture.source.cluster);
  (void)fixture.registry.put_cluster(fixture.target.cluster);
  const model::LinkState state = rng.below(5) == 0   ? model::LinkState::Down
                                : rng.below(3) == 0 ? model::LinkState::Degraded
                                : rng.below(9) == 0 ? model::LinkState::Unknown
                                                    : model::LinkState::Up;
  (void)fixture.registry.put_link(make_link("edge", fixture.source.endpoint, fixture.target.endpoint, state));
  if (rng.below(10) != 0) {
    (void)fixture.registry.put_path(
        make_path("path", fixture.source.endpoint, fixture.target.endpoint, {"edge"}));
  }
  (void)fixture.registry.put_policy(allow_rule("north-allow", "north", fixture.source.cluster.id,
                                               fixture.target.cluster.id, fixture.source.cluster.policy_generation.value(),
                                               true, rng.below(2) == 0, 0));
  if (rng.below(6) != 0) {
    (void)fixture.registry.put_policy(allow_rule("south-allow", "south", fixture.source.cluster.id,
                                                 fixture.target.cluster.id,
                                                 fixture.target.cluster.policy_generation.value(), true,
                                                 rng.below(2) == 0, 0));
  }
  if (rng.below(10) == 0) {
    (void)fixture.registry.put_policy(allow_rule("north-refuse", "north", fixture.source.cluster.id,
                                                 fixture.target.cluster.id,
                                                 fixture.source.cluster.policy_generation.value(), false));
  }
  fixture.registry.recompute_path_states();
  if (authorize && rng.below(3) != 0) {
    authorize_pair(fixture, rng, rng.below(4) != 0, CapacityUnits(500));
  }
  return fixture.registry;
}

}  // namespace

ICF_TEST(differential, engine_agrees_with_the_reference_model) {
  Rng rng(run_seed());
  constexpr int kIterations = 1500;
  std::size_t authorized_engine = 0;
  std::size_t authorized_reference = 0;
  std::size_t degraded_engine = 0;
  std::size_t degraded_reference = 0;
  for (int iteration = 0; iteration < kIterations; ++iteration) {
    PairFixture fixture;
    (void)random_registry(rng, fixture, true);
    const model::DecisionQuery query = query_for(fixture, 1 + rng.below(800));
    model::DecisionQuery effective = query;
    effective.allow_degraded = rng.below(2) == 0 ? true : fixture.source.cluster.endpoints[0].permits_degraded;
    const runtime::EngineView view = view_for(fixture);
    const model::Decision decision = runtime::decide(fixture.registry, effective, view);
    const ReferenceVerdict reference = reference_authorize(fixture.registry, effective, view);
    ICF_EXPECT_EQ(reference.authorized, decision.authorized());
    if (reference.authorized != decision.authorized()) {
      ICF_FAIL(std::string("disagreement: engine=") + to_string(decision.outcome) + " (" + decision.detail +
               ") reference=" + reference.first_failure);
    }
    if (reference.authorized) {
      ++authorized_reference;
      ICF_EXPECT_EQ(reference.degraded, decision.degraded);
      ICF_EXPECT_EQ(reference.grant, decision.grant);
      ICF_EXPECT_EQ(reference.contract, decision.contract);
      if (decision.outcome == Outcome::DegradedAuthorized) {
        ++degraded_engine;
      }
      if (reference.degraded) {
        ++degraded_reference;
      }
    }
    if (decision.authorized()) {
      ++authorized_engine;
    }
  }
  ICF_EXPECT_EQ(authorized_reference, authorized_engine);
  ICF_EXPECT_EQ(degraded_reference, degraded_engine);
  ICF_EXPECT_TRUE(authorized_engine > 0);
}

ICF_TEST(differential, reference_model_never_authorizes_without_consent) {
  Rng rng(run_seed());
  for (int iteration = 0; iteration < 400; ++iteration) {
    PairFixture fixture;
    (void)random_registry(rng, fixture, false);
    const model::DecisionQuery query = query_for(fixture, 100);
    model::DecisionQuery permissive = query;
    permissive.allow_degraded = true;
    const runtime::EngineView view = view_for(fixture);
    const ReferenceVerdict reference = reference_authorize(fixture.registry, permissive, view);
    ICF_EXPECT_FALSE(reference.authorized);
    ICF_EXPECT_FALSE(runtime::decide(fixture.registry, permissive, view).authorized());
  }
}
