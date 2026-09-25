// Inter-Cluster Fabric - authorization decisions.
//
// decide() answers, for one directed endpoint pair at one instant: is this connectivity
// authorized, under whose authority, and over which path. plan_fence() answers what must be
// withdrawn when a cluster reincarnates, withdraws consent, or changes its bound policy.
//
// Both functions are pure: they read a registry and return a value. They never mutate, never
// allocate unboundedly, and are deterministic for identical inputs.
#pragma once

#include "icf/model/decision.hpp"
#include "icf/model/registry.hpp"

namespace icf::runtime {

struct EngineView {
  Term term;
  IncarnationId incarnation;
  Timestamp now{};
};

[[nodiscard]] model::Decision decide(const model::Registry& registry, const model::DecisionQuery& query,
                                     const EngineView& view);

[[nodiscard]] model::FencePlan plan_fence(const model::Registry& registry, model::FenceTrigger trigger,
                                          const ClusterId& cluster, const IncarnationId& new_incarnation,
                                          const IncarnationId& previous_incarnation, const Generation& new_generation,
                                          Term term);

// Convenience: the plan for a coordinator reincarnation, which fences every grant issued by the
// previous coordinator incarnation.
[[nodiscard]] model::FencePlan plan_coordinator_fence(const model::Registry& registry,
                                                      const IncarnationId& previous_incarnation, Term term);

}  // namespace icf::runtime
