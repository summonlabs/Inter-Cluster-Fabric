#include "icf/model/policy.hpp"

#include <algorithm>
#include <map>

namespace icf::model {
namespace {

struct DomainRules {
  bool has_allow = false;
  bool has_refuse = false;
  bool allow_degraded = true;  // conjunction: every matching allow must permit degraded
  CapacityUnits max_capacity;
  bool has_capacity_limit = false;
  bool stale = false;
  std::vector<std::string> allow_ids;
  std::vector<std::string> refuse_ids;
};

void absorb(DomainRules& target, const PolicyRule& rule, bool generation_current) {
  if (!generation_current) {
    target.stale = true;
    return;
  }
  if (!rule.allow) {
    target.has_refuse = true;
    target.refuse_ids.push_back(rule.id);
    return;
  }
  target.has_allow = true;
  target.allow_ids.push_back(rule.id);
  if (!rule.allow_degraded) {
    target.allow_degraded = false;
  }
  if (rule.max_capacity.value() != 0) {
    if (!target.has_capacity_limit || rule.max_capacity < target.max_capacity) {
      target.max_capacity = rule.max_capacity;
      target.has_capacity_limit = true;
    }
  }
}

}  // namespace

PolicyEvaluation evaluate_policy(const Registry& registry, const ClusterRecord& source,
                                 const ClusterRecord& target, const EndpointId& endpoint_a,
                                 const EndpointId& endpoint_b) {
  PolicyEvaluation result;
  result.allow_degraded = true;

  std::map<AuthorityDomainId, DomainRules> per_domain;
  per_domain[source.domain];
  per_domain[target.domain];

  for (const auto& entry : registry.policies()) {
    const PolicyRule& rule = entry.second;
    const bool owned_here = rule.owner == source.domain || rule.owner == target.domain;
    if (!owned_here) {
      continue;
    }
    if (!rule.matches(source.id, target.id, endpoint_a, endpoint_b)) {
      continue;
    }
    // A rule is issued by an authority domain and speaks for the policy generation of *that
    // domain's* cluster: the rule's generation must equal the current generation of the cluster
    // the owner governs. A wildcard rule names no cluster and is therefore never stale.
    bool generation_current = true;
    if (rule.owner == source.domain && !rule.cluster_a.empty() && rule.cluster_a == source.id &&
        rule.generation != source.policy_generation) {
      generation_current = false;
    }
    if (rule.owner == target.domain && !rule.cluster_b.empty() && rule.cluster_b == target.id &&
        rule.generation != target.policy_generation) {
      generation_current = false;
    }
    absorb(per_domain[rule.owner], rule, generation_current);
  }

  bool any_refuse = false;
  bool any_stale = false;
  for (const auto& entry : per_domain) {
    const DomainRules& rules = entry.second;
    if (rules.has_refuse) {
      any_refuse = true;
      result.refusing_domains.push_back(entry.first);
      for (const std::string& id : rules.refuse_ids) {
        result.rule_ids.push_back(id);
      }
    }
    if (!rules.has_allow) {
      if (rules.stale) {
        any_stale = true;
      }
      result.missing_domains.push_back(entry.first);
    } else {
      if (!rules.allow_degraded) {
        result.allow_degraded = false;
      }
      if (rules.has_capacity_limit) {
        if (result.max_capacity.value() == 0 || rules.max_capacity < result.max_capacity) {
          result.max_capacity = rules.max_capacity;
        }
      }
      for (const std::string& id : rules.allow_ids) {
        result.rule_ids.push_back(id);
      }
    }
  }

  if (any_refuse) {
    result.decision = PolicyDecision::RefusedExplicitly;
    result.detail = "an explicit refuse rule from at least one authority domain covers this pair";
  } else if (!result.missing_domains.empty()) {
    result.decision = any_stale ? PolicyDecision::StaleGeneration : PolicyDecision::MissingAllowRule;
    result.detail = any_stale ? "only rules bound to a superseded policy generation match this pair"
                              : "no allow rule covers this pair from every authority domain";
  } else {
    result.decision = PolicyDecision::Allowed;
    result.detail = "both authority domains explicitly allow this pair";
  }
  std::sort(result.rule_ids.begin(), result.rule_ids.end());
  result.rule_ids.erase(std::unique(result.rule_ids.begin(), result.rule_ids.end()), result.rule_ids.end());
  return result;
}

}  // namespace icf::model
