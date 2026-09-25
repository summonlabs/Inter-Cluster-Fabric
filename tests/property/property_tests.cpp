// Seeded property and invariant tests.
//
// Every case is driven by the run seed printed by the harness, so a failure can be replayed
// exactly with --seed. The invariants here are the ones the runtime claims in its documentation:
// authorization requires two-sided consent, fencing is complete, replay cannot create authority,
// and accounting closes.
#include <algorithm>
#include <string>
#include <vector>

#include "harness.hpp"
#include "icf/model/policy.hpp"
#include "icf/runtime/engine.hpp"
#include "icf/runtime/fencing.hpp"
#include "icf/store/mutation.hpp"
#include "model_builder.hpp"

using namespace icf;
using namespace icf::test;

namespace {

model::Registry random_pair(Rng& rng, PairFixture& fixture, bool authorize) {
  const std::uint64_t generation_a = 1 + rng.below(1000000);
  const std::uint64_t generation_b = 1 + rng.below(1000000);
  const std::uint64_t policy_a = 1 + rng.below(1000);
  const std::uint64_t policy_b = 1 + rng.below(1000);
  fixture = PairFixture{};
  fixture.term = Term(1 + rng.below(1000));
  fixture.coordinator = IncarnationId::random(rng);
  fixture.now = Timestamp::from_unix_nanos(static_cast<std::int64_t>(1000000000 + rng.below(1000000000)));
  fixture.source = make_cluster("cluster-a", "domain-north", "a-scope", "/a", generation_a, policy_a, rng,
                                100 + rng.below(100000));
  fixture.target = make_cluster("cluster-b", "domain-south", "b-scope", "/b", generation_b, policy_b, rng,
                                100 + rng.below(100000));
  fixture.source.cluster.state = rng.below(10) == 0 ? model::ClusterState::Unknown : model::ClusterState::Active;
  fixture.target.cluster.state = rng.below(10) == 0 ? model::ClusterState::Unknown : model::ClusterState::Active;
  fixture.source.cluster.endpoints[0].permits_degraded = rng.below(2) == 0;
  fixture.target.cluster.endpoints[0].permits_degraded = rng.below(2) == 0;
  (void)fixture.registry.put_cluster(fixture.source.cluster);
  (void)fixture.registry.put_cluster(fixture.target.cluster);
  const model::LinkState link_state = rng.below(6) == 0   ? model::LinkState::Down
                                      : rng.below(4) == 0 ? model::LinkState::Degraded
                                      : rng.below(8) == 0 ? model::LinkState::Unknown
                                                          : model::LinkState::Up;
  (void)fixture.registry.put_link(make_link("edge-ab", fixture.source.endpoint, fixture.target.endpoint, link_state));
  (void)fixture.registry.put_path(
      make_path("path-ab", fixture.source.endpoint, fixture.target.endpoint, {"edge-ab"}));
  if (rng.below(8) != 0) {
    (void)fixture.registry.put_policy(allow_rule("allow-north", "domain-north", fixture.source.cluster.id,
                                                 fixture.target.cluster.id, policy_a, true,
                                                 rng.below(2) == 0, 0));
  }
  if (rng.below(8) != 0) {
    (void)fixture.registry.put_policy(allow_rule("allow-south", "domain-south", fixture.source.cluster.id,
                                                 fixture.target.cluster.id, policy_b, true,
                                                 rng.below(2) == 0, 0));
  }
  if (rng.below(16) == 0) {
    (void)fixture.registry.put_policy(allow_rule("refuse", "domain-north", fixture.source.cluster.id,
                                                 fixture.target.cluster.id, policy_a, false));
  }
  fixture.registry.recompute_path_states();
  if (authorize) {
    authorize_pair(fixture, rng, rng.below(8) != 0, CapacityUnits(100 + rng.below(1000)));
  }
  return fixture.registry;
}

// Independent restatement of the authorization requirements, evaluated directly against the
// registry rather than through the engine.
struct InvariantInputs {
  bool clusters_active = false;
  bool endpoints_active = false;
  bool policy_allows = false;
  bool path_live = false;
  bool path_degraded = false;
  bool degraded_permitted = false;
  bool contract_consented = false;
  bool grant_usable = false;
};

InvariantInputs gather(const model::Registry& registry, const PairFixture& fixture, const model::DecisionQuery& query,
                       const runtime::EngineView& view) {
  InvariantInputs inputs;
  const model::ClusterRecord* source = registry.find_cluster(fixture.source.cluster.id);
  const model::ClusterRecord* target = registry.find_cluster(fixture.target.cluster.id);
  inputs.clusters_active = source != nullptr && target != nullptr &&
                           source->state == model::ClusterState::Active &&
                           target->state == model::ClusterState::Active && !source->generation_conflict &&
                           !target->generation_conflict && !source->consent_withdrawn && !target->consent_withdrawn;
  if (source != nullptr && target != nullptr) {
    const model::PolicyEvaluation policy =
        model::evaluate_policy(registry, *source, *target, query.source, query.target);
    inputs.policy_allows = policy.decision == model::PolicyDecision::Allowed;
    inputs.degraded_permitted = policy.allow_degraded && query.allow_degraded;
    inputs.endpoints_active = source->endpoints[0].inter_cluster_allowed && target->endpoints[0].inter_cluster_allowed;
    inputs.degraded_permitted = inputs.degraded_permitted && source->endpoints[0].permits_degraded &&
                                target->endpoints[0].permits_degraded;
  }
  for (const auto& entry : registry.paths()) {
    if (entry.second.a != query.source || entry.second.b != query.target) {
      continue;
    }
    if (entry.second.state == model::PathState::Up) {
      inputs.path_live = true;
    }
    if (entry.second.state == model::PathState::Degraded) {
      inputs.path_live = true;
      inputs.path_degraded = true;
    }
  }
  for (const auto& entry : registry.contracts()) {
    const model::ContractRecord& contract = entry.second;
    if (contract.parties[0].endpoint != query.source || contract.parties[1].endpoint != query.target) {
      continue;
    }
    if (!contract.both_consented() || contract.state != model::ContractState::Consented) {
      continue;
    }
    bool consents_match = true;
    for (std::size_t side = 0; side < model::kPartyCount; ++side) {
      const model::ConsentRecord& consent = *contract.consents[side];
      const model::ClusterRecord* cluster = registry.find_cluster(contract.parties[side].cluster);
      if (cluster == nullptr || consent.terms_digest != contract.terms_digest ||
          consent.incarnation != cluster->incarnation || consent.generation != cluster->generation ||
          consent.policy_generation != cluster->policy_generation) {
        consents_match = false;
      }
    }
    if (!consents_match) {
      continue;
    }
    inputs.contract_consented = true;
    for (const auto& grant_entry : registry.grants()) {
      const model::GrantRecord& grant = grant_entry.second;
      if (grant.contract != contract.id || !grant.usable_state() || !grant.both_acknowledged()) {
        continue;
      }
      if (grant.coordinator_term != view.term || grant.coordinator != view.incarnation) {
        continue;
      }
      if (grant.valid_until < view.now) {
        continue;
      }
      bool bound = true;
      for (std::size_t side = 0; side < model::kPartyCount; ++side) {
        const model::ClusterRecord* cluster = registry.find_cluster(contract.parties[side].cluster);
        if (cluster == nullptr || grant.incarnations[side] != cluster->incarnation ||
            grant.generations[side] != cluster->generation || grant.policies[side] != cluster->policy_generation) {
          bound = false;
        }
      }
      if (bound && query.requested_capacity <= grant.capacity) {
        inputs.grant_usable = true;
      }
    }
  }
  return inputs;
}

}  // namespace

ICF_TEST(property, authorization_requires_every_condition) {
  Rng rng(run_seed());
  constexpr int kIterations = 400;
  std::size_t authorized = 0;
  for (int iteration = 0; iteration < kIterations; ++iteration) {
    PairFixture fixture;
    (void)random_pair(rng, fixture, rng.below(2) == 0);
    const model::DecisionQuery query = query_for(fixture, 1 + rng.below(2000));
    const runtime::EngineView view = view_for(fixture);
    const model::Decision decision = runtime::decide(fixture.registry, query, view);
    if (!decision.authorized()) {
      continue;
    }
    ++authorized;
    const InvariantInputs inputs = gather(fixture.registry, fixture, query, view);
    ICF_EXPECT_TRUE(inputs.clusters_active);
    ICF_EXPECT_TRUE(inputs.endpoints_active);
    ICF_EXPECT_TRUE(inputs.policy_allows);
    ICF_EXPECT_TRUE(inputs.path_live);
    ICF_EXPECT_TRUE(inputs.contract_consented);
    ICF_EXPECT_TRUE(inputs.grant_usable);
    if (decision.outcome == Outcome::Ok) {
      ICF_EXPECT_FALSE(decision.degraded);
    } else {
      ICF_EXPECT_EQ(Outcome::DegradedAuthorized, decision.outcome);
      ICF_EXPECT_TRUE(decision.degraded);
      ICF_EXPECT_TRUE(inputs.path_degraded);
      ICF_EXPECT_TRUE(inputs.degraded_permitted);
    }
    ICF_EXPECT_FALSE(decision.grant.is_nil());
    ICF_EXPECT_FALSE(decision.contract.is_nil());
  }
  ICF_EXPECT_TRUE(authorized > 0);
}

ICF_TEST(property, mutation_order_does_not_change_the_model_digest) {
  Rng rng(run_seed());
  for (int iteration = 0; iteration < 60; ++iteration) {
    PairFixture fixture;
    (void)random_pair(rng, fixture, true);
    // Mutations are shuffled within groups: grants refer to contracts and reservations refer to
    // grants, so those references stay ordered while everything else is permuted freely.
    std::vector<store::Mutation> mutations;
    for (const auto& entry : fixture.registry.clusters()) {
      store::Mutation mutation;
      mutation.kind = store::MutationKind::ClusterPut;
      mutation.cluster = entry.second;
      mutations.push_back(mutation);
    }
    for (const auto& entry : fixture.registry.links()) {
      store::Mutation mutation;
      mutation.kind = store::MutationKind::LinkPut;
      mutation.link = entry.second;
      mutations.push_back(mutation);
    }
    for (const auto& entry : fixture.registry.paths()) {
      store::Mutation mutation;
      mutation.kind = store::MutationKind::PathPut;
      mutation.path = entry.second;
      mutations.push_back(mutation);
    }
    for (const auto& entry : fixture.registry.policies()) {
      store::Mutation mutation;
      mutation.kind = store::MutationKind::PolicyPut;
      mutation.policy = entry.second;
      mutations.push_back(mutation);
    }
    for (const auto& entry : fixture.registry.contracts()) {
      store::Mutation mutation;
      mutation.kind = store::MutationKind::ContractPut;
      mutation.contract = entry.second;
      mutations.push_back(mutation);
    }
    const std::size_t independent_span = mutations.size();
    for (const auto& entry : fixture.registry.grants()) {
      store::Mutation mutation;
      mutation.kind = store::MutationKind::GrantPut;
      mutation.grant = entry.second;
      mutations.push_back(mutation);
    }

    std::vector<std::size_t> order(mutations.size());
    for (std::size_t index = 0; index < order.size(); ++index) {
      order[index] = index;
    }
    // Fisher-Yates within each group: the contract-free group is fully permuted, the dependent
    // group is permuted among itself.
    for (std::size_t index = independent_span; index > 1; --index) {
      const std::size_t pick = static_cast<std::size_t>(rng.below(index));
      std::swap(order[index - 1], order[pick]);
    }
    for (std::size_t index = order.size(); index > independent_span; --index) {
      const std::size_t pick = independent_span + static_cast<std::size_t>(rng.below(index - independent_span));
      std::swap(order[index - 1], order[pick]);
    }
    model::Registry shuffled;
    for (const std::size_t index : order) {
      const Status applied = store::apply_mutation(shuffled, mutations[index]);
      ICF_EXPECT_OK(applied);
    }
    ICF_EXPECT_EQ(fixture.registry.digest(), shuffled.digest());
    ICF_EXPECT_EQ(fixture.registry.counts().contracts, shuffled.counts().contracts);
  }
}

ICF_TEST(property, fencing_is_complete_and_accounting_closes) {
  Rng rng(run_seed());
  const model::FenceTrigger triggers[] = {
      model::FenceTrigger::ClusterReincarnation, model::FenceTrigger::ClusterWithdrawal,
      model::FenceTrigger::PolicyGenerationChange, model::FenceTrigger::Manual,
      model::FenceTrigger::GrantRevocation};
  for (int iteration = 0; iteration < 120; ++iteration) {
    PairFixture fixture;
    (void)random_pair(rng, fixture, true);
    if (fixture.registry.grants().empty()) {
      continue;
    }
    model::ClusterRecord reserved = *fixture.registry.find_cluster(fixture.source.cluster.id);
    reserved.endpoints[0].reserved = CapacityUnits(25);
    ICF_ASSERT_OK(fixture.registry.put_cluster(reserved));
    const GrantId first_grant = fixture.registry.grants().begin()->first;
    ICF_ASSERT_OK(fixture.registry.put_reservation(
        model::ReservationRecord{ReservationId::random(rng), first_grant, fixture.source.endpoint,
                                 fixture.source.cluster.id, CapacityUnits(25), false, fixture.now, Timestamp{},
                                 Revision(1), model::Provenance{}}));
    constexpr std::size_t kTriggerCount = 5;
    const model::FenceTrigger trigger = triggers[rng.below(kTriggerCount)];
    const model::FencePlan plan =
        runtime::plan_fence(fixture.registry, trigger, fixture.target.cluster.id, IncarnationId::random(rng),
                            fixture.target.cluster.incarnation, Generation(fixture.target.cluster.generation.value() + 1),
                            fixture.term);
    Result<runtime::FenceOutcome> outcome =
        runtime::apply_fence_plan(fixture.registry, plan, fixture.now, "property");
    ICF_ASSERT_OK(outcome.status());

    for (const auto& entry : fixture.registry.reservations()) {
      ICF_EXPECT_TRUE(entry.second.released);
    }
    const model::ClusterRecord* source = fixture.registry.find_cluster(fixture.source.cluster.id);
    ICF_ASSERT_TRUE(source != nullptr);
    ICF_EXPECT_EQ(0ull, source->endpoints[0].reserved.value());
    const model::Decision decision = runtime::decide(fixture.registry, query_for(fixture), view_for(fixture));
    ICF_EXPECT_FALSE(decision.authorized());
  }
}

ICF_TEST(property, stale_incarnations_never_reauthorize) {
  Rng rng(run_seed());
  for (int iteration = 0; iteration < 120; ++iteration) {
    PairFixture fixture;
    (void)random_pair(rng, fixture, true);
    if (fixture.registry.grants().empty()) {
      continue;
    }
    // Remember the old consent, then bump the far side's incarnation and generation.
    const model::ConsentRecord stale_consent = *fixture.registry.find_contract(fixture.contract)->consents[1];
    model::ClusterRecord reincarnated = *fixture.registry.find_cluster(fixture.target.cluster.id);
    reincarnated.incarnation = IncarnationId::random(rng);
    reincarnated.generation = Generation(reincarnated.generation.value() + 1 + rng.below(10));
    ICF_ASSERT_OK(fixture.registry.put_cluster(reincarnated));

    // Replaying the old consent must not restore authority.
    model::ContractRecord* contract = fixture.registry.find_contract(fixture.contract);
    contract->consents[1] = stale_consent;
    contract->state = model::ContractState::Consented;
    const model::Decision decision = runtime::decide(fixture.registry, query_for(fixture), view_for(fixture));
    ICF_EXPECT_FALSE(decision.authorized());

    // A grant bound to the old incarnation is fenced by the plan and stays fenced.
    const model::FencePlan plan =
        runtime::plan_fence(fixture.registry, model::FenceTrigger::ClusterReincarnation, reincarnated.id,
                            reincarnated.incarnation, stale_consent.incarnation, reincarnated.generation, fixture.term);
    Result<runtime::FenceOutcome> outcome = runtime::apply_fence_plan(fixture.registry, plan, fixture.now, "property");
    ICF_ASSERT_OK(outcome.status());
    ICF_EXPECT_FALSE(runtime::decide(fixture.registry, query_for(fixture), view_for(fixture)).authorized());
  }
}

ICF_TEST(property, encoding_round_trip_preserves_every_bit_of_meaning) {
  Rng rng(run_seed());
  for (int iteration = 0; iteration < 80; ++iteration) {
    PairFixture fixture;
    (void)random_pair(rng, fixture, true);
    ByteWriter writer;
    model::encode_registry(fixture.registry, writer, true);
    ByteReader reader(writer.data());
    Result<model::Registry> decoded = model::decode_registry(reader);
    ICF_ASSERT_TRUE(decoded.has_value());
    ICF_EXPECT_OK(reader.expect_end());
    ICF_EXPECT_EQ(fixture.registry.digest(), decoded.value().digest());
    ICF_EXPECT_EQ(fixture.registry.counts().clusters, decoded.value().counts().clusters);
    ICF_EXPECT_EQ(fixture.registry.counts().links, decoded.value().counts().links);
    ICF_EXPECT_EQ(fixture.registry.counts().paths, decoded.value().counts().paths);
    ICF_EXPECT_EQ(fixture.registry.counts().policies, decoded.value().counts().policies);
    ICF_EXPECT_EQ(fixture.registry.counts().grants, decoded.value().counts().grants);
  }
}

ICF_TEST(property, decision_outcome_family_is_consistent) {
  Rng rng(run_seed());
  for (int iteration = 0; iteration < 400; ++iteration) {
    PairFixture fixture;
    (void)random_pair(rng, fixture, rng.below(2) == 0);
    const model::DecisionQuery query = query_for(fixture, 1 + rng.below(2000));
    const model::Decision decision = runtime::decide(fixture.registry, query, view_for(fixture));
    // A decision that is not authorized must never carry a usable grant reference without a
    // reason explaining why it is not authorized.
    if (!decision.authorized()) {
      ICF_EXPECT_FALSE(decision.reasons.empty());
      ICF_EXPECT_FALSE(decision.detail.empty());
    }
    ICF_EXPECT_EQ(fixture.registry.digest(), decision.view_digest);
    ICF_EXPECT_TRUE(decision.decided_at == fixture.now);
    if (decision.outcome == Outcome::DegradedAuthorized) {
      ICF_EXPECT_TRUE(decision.degraded);
    }
    if (decision.outcome == Outcome::Ok) {
      ICF_EXPECT_FALSE(decision.degraded);
    }
  }
}
