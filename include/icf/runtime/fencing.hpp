// Inter-Cluster Fabric - applying fence plans.
//
// A fence plan is a description; applying it is what actually withdraws connectivity authority.
// Application is idempotent: fencing an already-fenced grant is reported as such, and a released
// reservation is never released twice. Capacity accounting closes here: when a grant is fenced
// the capacity it reserved returns to the endpoint and link counters.
#pragma once

#include "icf/model/decision.hpp"
#include "icf/model/registry.hpp"

namespace icf::runtime {

struct FenceOutcome {
  std::uint64_t grants_fenced = 0;
  std::uint64_t contracts_fenced = 0;
  std::uint64_t reservations_released = 0;
  std::uint64_t capacity_released = 0;
  std::uint64_t already_fenced = 0;
};

// Applies every action in the plan. Never fails for an already-applied action; returns a
// negative status only when the registry refuses a transition outright.
[[nodiscard]] Result<FenceOutcome> apply_fence_plan(model::Registry& registry, const model::FencePlan& plan,
                                                    Timestamp at, std::string actor);

// Marks every dynamic record that survived a recovery as historical. Recovered grants stay in
// the registry for accounting, but their state is set to Fenced so no decision can use them.
[[nodiscard]] Result<FenceOutcome> fence_recovered_state(model::Registry& registry, Timestamp at,
                                                         std::string actor, const IncarnationId& previous_incarnation,
                                                         Term term);

}  // namespace icf::runtime
