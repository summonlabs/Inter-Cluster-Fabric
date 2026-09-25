#include <string>

#include "harness.hpp"
#include "icf/runtime/engine.hpp"
#include "icf/runtime/fencing.hpp"
#include "model_builder.hpp"

using namespace icf;
using namespace icf::test;

namespace {

model::ClusterRecord bump_generation(const model::ClusterRecord& cluster, std::uint64_t generation) {
  model::ClusterRecord updated = cluster;
  updated.generation = Generation(generation);
  return updated;
}

}  // namespace

ICF_TEST(engine, authorized_pair_is_ok) {
  Rng rng(51);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  const model::Decision decision = runtime::decide(fixture.registry, query_for(fixture), view_for(fixture));
  ICF_EXPECT_EQ(Outcome::Ok, decision.outcome);
  ICF_EXPECT_TRUE(decision.authorized());
  ICF_EXPECT_FALSE(decision.degraded);
  ICF_EXPECT_EQ(fixture.contract, decision.contract);
  ICF_EXPECT_EQ(fixture.grant, decision.grant);
  ICF_EXPECT_EQ(std::string("domain-north"), decision.authorities[0].str());
  ICF_EXPECT_EQ(std::string("domain-south"), decision.authorities[1].str());
  ICF_EXPECT_EQ(static_cast<std::size_t>(1), decision.paths.size());
  ICF_EXPECT_EQ(fixture.registry.digest(), decision.view_digest);
}

ICF_TEST(engine, unregistered_endpoints_are_not_found) {
  Rng rng(52);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  model::DecisionQuery query = query_for(fixture);
  query.source = EndpointId::parse("does-not-exist").value();
  const model::Decision decision = runtime::decide(fixture.registry, query, view_for(fixture));
  ICF_EXPECT_EQ(Outcome::NotFound, decision.outcome);
  ICF_EXPECT_TRUE(std::find(decision.reasons.begin(), decision.reasons.end(),
                            model::ReasonCode::SourceEndpointNotRegistered) != decision.reasons.end());

  model::DecisionQuery same = query_for(fixture);
  same.target = same.source;
  ICF_EXPECT_EQ(Outcome::Invalid, runtime::decide(fixture.registry, same, view_for(fixture)).outcome);
}

ICF_TEST(engine, unknown_state_is_unknown_not_denied) {
  Rng rng(53);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  model::ClusterRecord unknown = fixture.target.cluster;
  unknown.state = model::ClusterState::Unknown;
  ICF_ASSERT_OK(fixture.registry.put_cluster(unknown));
  const model::Decision decision = runtime::decide(fixture.registry, query_for(fixture), view_for(fixture));
  ICF_EXPECT_EQ(Outcome::Unknown, decision.outcome);
  ICF_EXPECT_FALSE(decision.authorized());
}

ICF_TEST(engine, administrative_refusal_is_refused) {
  Rng rng(54);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  ICF_ASSERT_OK(fixture.registry.put_policy(allow_rule("refuse", "domain-south", fixture.source.cluster.id,
                                                       fixture.target.cluster.id,
                                                       fixture.target.cluster.policy_generation.value(), false)));
  const model::Decision decision = runtime::decide(fixture.registry, query_for(fixture), view_for(fixture));
  ICF_EXPECT_EQ(Outcome::Refused, decision.outcome);

  model::ClusterRecord suspended = fixture.target.cluster;
  suspended.state = model::ClusterState::Suspended;
  ICF_ASSERT_OK(fixture.registry.put_cluster(suspended));
  ICF_EXPECT_EQ(Outcome::Refused, runtime::decide(fixture.registry, query_for(fixture), view_for(fixture)).outcome);

  model::ClusterRecord draining = fixture.target.cluster;
  draining.state = model::ClusterState::Draining;
  ICF_ASSERT_OK(fixture.registry.put_cluster(draining));
  ICF_EXPECT_EQ(Outcome::Refused, runtime::decide(fixture.registry, query_for(fixture), view_for(fixture)).outcome);

  model::ClusterRecord retired = fixture.target.cluster;
  retired.state = model::ClusterState::Retired;
  ICF_ASSERT_OK(fixture.registry.put_cluster(retired));
  ICF_EXPECT_EQ(Outcome::Fenced, runtime::decide(fixture.registry, query_for(fixture), view_for(fixture)).outcome);

  model::ClusterRecord withdrawn = fixture.target.cluster;
  withdrawn.consent_withdrawn = true;
  ICF_ASSERT_OK(fixture.registry.put_cluster(withdrawn));
  ICF_EXPECT_EQ(Outcome::Refused, runtime::decide(fixture.registry, query_for(fixture), view_for(fixture)).outcome);
}

ICF_TEST(engine, missing_allow_rule_is_unauthorized) {
  Rng rng(55);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  fixture.registry.policies().clear();
  const model::Decision decision = runtime::decide(fixture.registry, query_for(fixture), view_for(fixture));
  ICF_EXPECT_EQ(Outcome::Unauthorized, decision.outcome);
}

ICF_TEST(engine, no_contract_is_unauthorized_and_partial_consent_is_incomplete) {
  Rng rng(56);
  PairFixture fixture = make_authorized_pair(rng);
  ICF_EXPECT_EQ(Outcome::Unauthorized, runtime::decide(fixture.registry, query_for(fixture), view_for(fixture)).outcome);

  authorize_pair(fixture, rng, false);
  // A consented contract without a grant is incomplete, never authorized.
  const model::Decision decision = runtime::decide(fixture.registry, query_for(fixture), view_for(fixture));
  ICF_EXPECT_EQ(Outcome::Incomplete, decision.outcome);
  ICF_EXPECT_FALSE(decision.authorized());

  model::ContractRecord* contract = fixture.registry.find_contract(fixture.contract);
  ICF_ASSERT_TRUE(contract != nullptr);
  contract->consents[1].reset();
  contract->state = model::ContractState::AwaitingConsent;
  ICF_EXPECT_EQ(Outcome::Incomplete, runtime::decide(fixture.registry, query_for(fixture), view_for(fixture)).outcome);
}

ICF_TEST(engine, conflicting_consents_are_conflicting) {
  Rng rng(57);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  model::ContractRecord* contract = fixture.registry.find_contract(fixture.contract);
  ICF_ASSERT_TRUE(contract != nullptr);
  contract->consents[1]->terms_digest = Sha256::hash(std::string_view("different terms"));
  const model::Decision decision = runtime::decide(fixture.registry, query_for(fixture), view_for(fixture));
  ICF_EXPECT_EQ(Outcome::Conflicting, decision.outcome);
}

ICF_TEST(engine, stale_incarnation_generation_and_policy_are_stale_or_fenced) {
  Rng rng(58);
  {
    PairFixture fixture = make_authorized_pair(rng);
    authorize_pair(fixture, rng);
    model::ClusterRecord reincarnated = fixture.target.cluster;
    reincarnated.incarnation = IncarnationId::random(rng);
    reincarnated.generation = Generation(fixture.target.cluster.generation.value() + 1);
    ICF_ASSERT_OK(fixture.registry.put_cluster(reincarnated));
    // A consent or grant bound to a superseded incarnation is FENCED/STALE, never authorized.
    const Outcome outcome = runtime::decide(fixture.registry, query_for(fixture), view_for(fixture)).outcome;
    ICF_EXPECT_TRUE(outcome == Outcome::Fenced || outcome == Outcome::Stale);
  }
  {
    PairFixture fixture = make_authorized_pair(rng);
    authorize_pair(fixture, rng);
    ICF_ASSERT_OK(
        fixture.registry.put_cluster(bump_generation(fixture.target.cluster, 10)));
    ICF_EXPECT_EQ(Outcome::Stale, runtime::decide(fixture.registry, query_for(fixture), view_for(fixture)).outcome);
  }
  {
    PairFixture fixture = make_authorized_pair(rng);
    authorize_pair(fixture, rng);
    model::ClusterRecord bumped = fixture.target.cluster;
    bumped.policy_generation = PolicyGeneration(9);
    ICF_ASSERT_OK(fixture.registry.put_cluster(bumped));
    const model::Decision decision = runtime::decide(fixture.registry, query_for(fixture), view_for(fixture));
    ICF_EXPECT_TRUE(decision.outcome == Outcome::Stale || decision.outcome == Outcome::Unauthorized);
  }
  {
    PairFixture fixture = make_authorized_pair(rng);
    authorize_pair(fixture, rng);
    model::DecisionQuery query = query_for(fixture);
    query.expect_source_generation = true;
    query.source_generation = Generation(99);
    ICF_EXPECT_EQ(Outcome::Stale, runtime::decide(fixture.registry, query, view_for(fixture)).outcome);
  }
}

ICF_TEST(engine, grant_lifecycle_outcomes_are_distinct) {
  Rng rng(59);
  const model::GrantState states[] = {model::GrantState::Preparing, model::GrantState::Prepared,
                                      model::GrantState::Indeterminate, model::GrantState::Aborted,
                                      model::GrantState::Fenced, model::GrantState::Expired,
                                      model::GrantState::Withdrawn};
  const Outcome expected[] = {Outcome::Incomplete, Outcome::Incomplete, Outcome::Indeterminate, Outcome::Fenced,
                              Outcome::Fenced, Outcome::Expired, Outcome::Fenced};
  constexpr std::size_t kStateCount = 7;
  for (std::size_t index = 0; index < kStateCount; ++index) {
    PairFixture fixture = make_authorized_pair(rng);
    authorize_pair(fixture, rng);
    fixture.registry.find_grant(fixture.grant)->state = states[index];
    const model::Decision decision = runtime::decide(fixture.registry, query_for(fixture), view_for(fixture));
    ICF_EXPECT_EQ(expected[index], decision.outcome);
  }

  PairFixture unacknowledged = make_authorized_pair(rng);
  authorize_pair(unacknowledged, rng);
  unacknowledged.registry.find_grant(unacknowledged.grant)->acknowledged[1] = false;
  ICF_EXPECT_EQ(Outcome::Incomplete,
                runtime::decide(unacknowledged.registry, query_for(unacknowledged), view_for(unacknowledged)).outcome);

  PairFixture superseded_term = make_authorized_pair(rng);
  authorize_pair(superseded_term, rng);
  runtime::EngineView view = view_for(superseded_term);
  view.term = Term(99);
  ICF_EXPECT_EQ(Outcome::Fenced,
                runtime::decide(superseded_term.registry, query_for(superseded_term), view).outcome);

  PairFixture expired = make_authorized_pair(rng);
  authorize_pair(expired, rng);
  runtime::EngineView later = view_for(expired);
  later.now = later.now.plus(Duration::from_minutes(30));
  ICF_EXPECT_EQ(Outcome::Expired, runtime::decide(expired.registry, query_for(expired), later).outcome);

  PairFixture over_capacity = make_authorized_pair(rng);
  authorize_pair(over_capacity, rng);
  ICF_EXPECT_EQ(Outcome::CapacityExceeded,
                runtime::decide(over_capacity.registry, query_for(over_capacity, 100000), view_for(over_capacity)).outcome);
}

ICF_TEST(engine, partition_degraded_and_unsupported_paths) {
  Rng rng(60);
  {
    PairFixture fixture = make_authorized_pair(rng);
    authorize_pair(fixture, rng);
    model::LinkRecord down = *fixture.registry.find_link(EdgeId::parse("edge-ab").value());
    down.state = model::LinkState::Down;
    ICF_ASSERT_OK(fixture.registry.put_link(down));
    fixture.registry.recompute_path_states();
    ICF_EXPECT_EQ(Outcome::Partitioned, runtime::decide(fixture.registry, query_for(fixture), view_for(fixture)).outcome);
  }
  {
    PairFixture fixture = make_authorized_pair(rng);
    authorize_pair(fixture, rng);
    model::LinkRecord degraded = *fixture.registry.find_link(EdgeId::parse("edge-ab").value());
    degraded.state = model::LinkState::Degraded;
    ICF_ASSERT_OK(fixture.registry.put_link(degraded));
    fixture.registry.recompute_path_states();
    // Degraded connectivity is authorized but reported distinctly, and only when the caller
    // accepts a degraded path and both the policy and the endpoint scopes permit it.
    model::DecisionQuery degraded_query = query_for(fixture);
    degraded_query.allow_degraded = true;
    ICF_EXPECT_EQ(Outcome::DegradedAuthorized,
                  runtime::decide(fixture.registry, degraded_query, view_for(fixture)).outcome);

    model::ClusterRecord strict = fixture.source.cluster;
    strict.endpoints[0].permits_degraded = false;
    ICF_ASSERT_OK(fixture.registry.put_cluster(strict));
    model::DecisionQuery strict_query = query_for(fixture);
    strict_query.allow_degraded = true;
    const model::Decision decision = runtime::decide(fixture.registry, strict_query, view_for(fixture));
    ICF_EXPECT_EQ(Outcome::Unauthorized, decision.outcome);
    ICF_EXPECT_TRUE(std::find(decision.reasons.begin(), decision.reasons.end(),
                              model::ReasonCode::PathNotPermittedDegraded) != decision.reasons.end());
  }
  {
    PairFixture fixture = make_authorized_pair(rng);
    authorize_pair(fixture, rng);
    model::LinkRecord unsupported = *fixture.registry.find_link(EdgeId::parse("edge-ab").value());
    unsupported.kind = model::LinkKind::OpticalInterconnect;
    ICF_ASSERT_OK(fixture.registry.put_link(unsupported));
    fixture.registry.recompute_path_states();
    ICF_EXPECT_EQ(Outcome::Unsupported,
                  runtime::decide(fixture.registry, query_for(fixture), view_for(fixture)).outcome);
  }
  {
    PairFixture fixture = make_authorized_pair(rng);
    authorize_pair(fixture, rng);
    model::LinkRecord unknown = *fixture.registry.find_link(EdgeId::parse("edge-ab").value());
    unknown.state = model::LinkState::Unknown;
    ICF_ASSERT_OK(fixture.registry.put_link(unknown));
    fixture.registry.recompute_path_states();
    ICF_EXPECT_EQ(Outcome::Unknown, runtime::decide(fixture.registry, query_for(fixture), view_for(fixture)).outcome);
  }
}

ICF_TEST(engine, generation_conflict_is_conflicting) {
  Rng rng(61);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  model::ClusterRecord conflicted = fixture.target.cluster;
  conflicted.generation_conflict = true;
  conflicted.conflicting_generation = conflicted.generation;
  ICF_ASSERT_OK(fixture.registry.put_cluster(conflicted));
  ICF_EXPECT_EQ(Outcome::Conflicting, runtime::decide(fixture.registry, query_for(fixture), view_for(fixture)).outcome);
}

ICF_TEST(engine, fence_plan_covers_grants_contracts_and_reservations) {
  Rng rng(62);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  const ReservationId reservation = ReservationId::random(rng);
  ICF_ASSERT_OK(fixture.registry
                    .put_reservation(model::ReservationRecord{reservation, fixture.grant, fixture.source.endpoint,
                                                              fixture.source.cluster.id, CapacityUnits(50), false,
                                                              fixture.now, Timestamp{}, Revision(1),
                                                              model::Provenance{}})
                    );

  const model::FencePlan plan =
      runtime::plan_fence(fixture.registry, model::FenceTrigger::ClusterReincarnation, fixture.target.cluster.id,
                          IncarnationId::random(rng), fixture.target.cluster.incarnation, Generation(10), fixture.term);
  std::size_t grants = 0;
  std::size_t contracts = 0;
  std::size_t reservations = 0;
  for (const model::FenceAction& action : plan.actions) {
    if (action.target == model::FenceTarget::Grant) {
      ++grants;
    } else if (action.target == model::FenceTarget::Contract) {
      ++contracts;
    } else {
      ++reservations;
    }
  }
  ICF_EXPECT_EQ(static_cast<std::size_t>(1), grants);
  ICF_EXPECT_EQ(static_cast<std::size_t>(1), contracts);
  ICF_EXPECT_EQ(static_cast<std::size_t>(1), reservations);
  ICF_EXPECT_EQ(fixture.grant, plan.actions.front().grant);

  // The plan is deterministic: the same inputs produce the same actions in the same order.
  const model::FencePlan again =
      runtime::plan_fence(fixture.registry, model::FenceTrigger::ClusterReincarnation, fixture.target.cluster.id,
                          plan.incarnation, fixture.target.cluster.incarnation, Generation(10), fixture.term);
  ICF_EXPECT_EQ(plan.actions.size(), again.actions.size());
  ICF_EXPECT_EQ(plan.actions.front().grant, again.actions.front().grant);
}

ICF_TEST(engine, applying_a_fence_plan_withdraws_authority_and_closes_accounting) {
  Rng rng(63);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  // Give the endpoint a reserved amount so accounting has something to close.
  model::ClusterRecord reserved = fixture.source.cluster;
  reserved.endpoints[0].reserved = CapacityUnits(50);
  ICF_ASSERT_OK(fixture.registry.put_cluster(reserved));
  ICF_ASSERT_OK(fixture.registry
                    .put_reservation(model::ReservationRecord{ReservationId::random(rng), fixture.grant,
                                                              fixture.source.endpoint, fixture.source.cluster.id,
                                                              CapacityUnits(50), false, fixture.now, Timestamp{},
                                                              Revision(1), model::Provenance{}})
                    );

  const model::FencePlan plan =
      runtime::plan_fence(fixture.registry, model::FenceTrigger::ClusterWithdrawal, fixture.target.cluster.id,
                          fixture.target.cluster.incarnation, fixture.target.cluster.incarnation,
                          fixture.target.cluster.generation, fixture.term);
  Result<runtime::FenceOutcome> outcome =
      runtime::apply_fence_plan(fixture.registry, plan, fixture.now, "test");
  ICF_ASSERT_OK(outcome.status());
  ICF_EXPECT_EQ(1ull, outcome.value().grants_fenced);
  ICF_EXPECT_EQ(1ull, outcome.value().reservations_released);
  ICF_EXPECT_EQ(50ull, outcome.value().capacity_released);

  const model::ClusterRecord* source = fixture.registry.find_cluster(fixture.source.cluster.id);
  ICF_ASSERT_TRUE(source != nullptr);
  ICF_EXPECT_EQ(0ull, source->endpoints[0].reserved.value());
  for (const auto& entry : fixture.registry.reservations()) {
    ICF_EXPECT_TRUE(entry.second.released);
  }
  ICF_EXPECT_EQ(Outcome::Fenced, runtime::decide(fixture.registry, query_for(fixture), view_for(fixture)).outcome);

  // Applying the same plan twice is idempotent and never releases capacity twice.
  Result<runtime::FenceOutcome> second =
      runtime::apply_fence_plan(fixture.registry, plan, fixture.now, "test");
  ICF_ASSERT_OK(second.status());
  ICF_EXPECT_EQ(0ull, second.value().grants_fenced);
  ICF_EXPECT_EQ(0ull, second.value().reservations_released);
  ICF_EXPECT_TRUE(second.value().already_fenced >= 2);
  const model::ClusterRecord* still_zero = fixture.registry.find_cluster(fixture.source.cluster.id);
  ICF_EXPECT_EQ(0ull, still_zero->endpoints[0].reserved.value());
}

ICF_TEST(engine, recovered_state_fencing_blocks_every_recovered_grant) {
  Rng rng(64);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  Result<runtime::FenceOutcome> outcome =
      runtime::fence_recovered_state(fixture.registry, fixture.now, "test", IncarnationId{}, fixture.term);
  ICF_ASSERT_OK(outcome.status());
  ICF_EXPECT_EQ(1ull, outcome.value().grants_fenced);
  ICF_EXPECT_EQ(Outcome::Fenced, runtime::decide(fixture.registry, query_for(fixture), view_for(fixture)).outcome);
}

ICF_TEST(engine, coordinator_reincarnation_fences_only_the_previous_incarnation) {
  Rng rng(65);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  model::GrantRecord newer = *fixture.registry.find_grant(fixture.grant);
  newer.id = GrantId::random(rng);
  newer.coordinator = IncarnationId::random(rng);
  newer.issued_at = fixture.now.plus(Duration::from_seconds(1));
  ICF_ASSERT_OK(fixture.registry.put_grant(newer));

  const model::FencePlan plan = runtime::plan_coordinator_fence(fixture.registry, fixture.coordinator, fixture.term);
  bool fences_old = false;
  bool fences_new = false;
  for (const model::FenceAction& action : plan.actions) {
    if (action.target != model::FenceTarget::Grant) {
      continue;
    }
    if (action.grant == fixture.grant) {
      fences_old = true;
    }
    if (action.grant == newer.id) {
      fences_new = true;
    }
  }
  ICF_EXPECT_TRUE(fences_old);
  ICF_EXPECT_FALSE(fences_new);
}

ICF_TEST(engine, decision_is_deterministic_across_repeated_evaluation) {
  Rng rng(66);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  const model::Decision first = runtime::decide(fixture.registry, query_for(fixture), view_for(fixture));
  for (int index = 0; index < 16; ++index) {
    const model::Decision again = runtime::decide(fixture.registry, query_for(fixture), view_for(fixture));
    ICF_EXPECT_EQ(first.outcome, again.outcome);
    ICF_EXPECT_EQ(first.grant, again.grant);
    ICF_EXPECT_EQ(first.view_digest, again.view_digest);
    ICF_EXPECT_EQ(first.reasons.size(), again.reasons.size());
  }
}
