// Inter-Cluster Fabric - two-domain policy evaluation.
//
// Policy is deny-by-default and two-sided: a cross-cluster decision needs an explicit allow
// from *each* administrative domain. An explicit refuse from either domain wins over any
// allow. A rule that matches but carries a stale policy generation produces STALE, not a
// silent fallback to an older rule.
#pragma once

#include <string>
#include <vector>

#include "icf/model/registry.hpp"

namespace icf::model {

enum class PolicyDecision : std::uint8_t {
  Allowed = 0,
  RefusedExplicitly = 1,   // a matching rule refuses -> REFUSED
  MissingAllowRule = 2,    // no allow rule from one domain -> UNAUTHORIZED
  StaleGeneration = 3,     // only stale-generation rules match -> STALE
  Unsupported = 4,         // the decision cannot be expressed (e.g. non-derivable subject)
};

struct PolicyEvaluation {
  PolicyDecision decision = PolicyDecision::MissingAllowRule;
  std::vector<std::string> rule_ids;
  std::vector<AuthorityDomainId> missing_domains;
  std::vector<AuthorityDomainId> refusing_domains;
  bool allow_degraded = false;
  CapacityUnits max_capacity;
  std::string detail;
};

// Evaluates policy for a directed pair. Both domains must explicitly allow the pair.
[[nodiscard]] PolicyEvaluation evaluate_policy(const Registry& registry, const ClusterRecord& source,
                                               const ClusterRecord& target, const EndpointId& endpoint_a,
                                               const EndpointId& endpoint_b);

}  // namespace icf::model
