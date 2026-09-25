// An independent reference implementation of the authorization predicate.
//
// This file deliberately shares no code with the decision engine. It computes the answer with
// explicit set operations over the registry and a separate control flow, so that a mistake in
// either implementation shows up as a disagreement when both are run over the same state.
#pragma once

#include <set>
#include <string>

#include "icf/model/policy.hpp"
#include "icf/model/registry.hpp"

namespace icf::test {

struct ReferenceVerdict {
  bool authorized = false;
  bool degraded = false;
  std::string first_failure;
  ContractId contract;
  GrantId grant;
};

// Collects every endpoint scope as (cluster, endpoint) pairs in one pass.
inline std::set<EndpointId> all_endpoints(const model::Registry& registry) {
  std::set<EndpointId> endpoints;
  for (const auto& cluster : registry.clusters()) {
    for (const model::EndpointRecord& endpoint : cluster.second.endpoints) {
      endpoints.insert(endpoint.id);
    }
  }
  return endpoints;
}

inline const model::ClusterRecord* cluster_of(const model::Registry& registry, const EndpointId& endpoint) {
  for (const auto& entry : registry.clusters()) {
    for (const model::EndpointRecord& candidate : entry.second.endpoints) {
      if (candidate.id == endpoint) {
        return &entry.second;
      }
    }
  }
  return nullptr;
}

inline ReferenceVerdict reference_authorize(const model::Registry& registry, const model::DecisionQuery& query,
                                            const runtime::EngineView& view) {
  ReferenceVerdict verdict;
  const std::set<EndpointId> endpoints = all_endpoints(registry);
  if (query.source == query.target) {
    verdict.first_failure = "identical endpoints";
    return verdict;
  }
  if (endpoints.count(query.source) == 0 || endpoints.count(query.target) == 0) {
    verdict.first_failure = "endpoint not registered";
    return verdict;
  }
  const model::ClusterRecord* source = cluster_of(registry, query.source);
  const model::ClusterRecord* target = cluster_of(registry, query.target);
  if (source == nullptr || target == nullptr) {
    verdict.first_failure = "cluster not registered";
    return verdict;
  }
  for (const model::ClusterRecord* cluster : {source, target}) {
    if (cluster->state != model::ClusterState::Active) {
      verdict.first_failure = "cluster not active";
      return verdict;
    }
    if (cluster->generation_conflict) {
      verdict.first_failure = "generation conflict";
      return verdict;
    }
    if (cluster->consent_withdrawn) {
      verdict.first_failure = "consent withdrawn";
      return verdict;
    }
  }
  for (const model::ClusterRecord* cluster : {source, target}) {
    for (const model::EndpointRecord& endpoint : cluster->endpoints) {
      if (endpoint.id != query.source && endpoint.id != query.target) {
        continue;
      }
      if (endpoint.state != model::EndpointState::Active || !endpoint.inter_cluster_allowed) {
        verdict.first_failure = "endpoint not usable";
        return verdict;
      }
    }
  }
  if (query.expect_source_generation && query.source_generation != source->generation) {
    verdict.first_failure = "stale source generation";
    return verdict;
  }
  if (query.expect_target_generation && query.target_generation != target->generation) {
    verdict.first_failure = "stale target generation";
    return verdict;
  }
  const model::PolicyEvaluation policy =
      model::evaluate_policy(registry, *source, *target, query.source, query.target);
  if (policy.decision != model::PolicyDecision::Allowed) {
    verdict.first_failure = "policy does not allow the pair";
    return verdict;
  }

  // Path set: any registered path between the pair that is not down.
  bool live = false;
  bool degraded_only = true;
  bool unsupported_only = true;
  for (const auto& entry : registry.paths()) {
    const model::PathRecord& path = entry.second;
    const bool forward = path.a == query.source && path.b == query.target;
    const bool backward = path.a == query.target && path.b == query.source;
    if (!forward && !backward) {
      continue;
    }
    if (path.contains_unsupported_edge) {
      continue;
    }
    unsupported_only = false;
    if (path.state == model::PathState::Up) {
      live = true;
      degraded_only = false;
    } else if (path.state == model::PathState::Degraded) {
      live = true;
    }
  }
  if (!live) {
    verdict.first_failure = unsupported_only ? "only unsupported paths" : "no live path";
    return verdict;
  }
  if (degraded_only) {
    if (!query.allow_degraded || !policy.allow_degraded) {
      verdict.first_failure = "degraded not permitted";
      return verdict;
    }
    for (const model::ClusterRecord* cluster : {source, target}) {
      for (const model::EndpointRecord& endpoint : cluster->endpoints) {
        if (endpoint.id != query.source && endpoint.id != query.target) {
          continue;
        }
        if (!endpoint.permits_degraded) {
          verdict.first_failure = "degraded not permitted by endpoint";
          return verdict;
        }
      }
    }
  }

  // Contract set: exactly the contracts that name this endpoint pair in either direction.
  bool found_contract = false;
  for (const auto& entry : registry.contracts()) {
    const model::ContractRecord& contract = entry.second;
    const bool forward = contract.parties[0].endpoint == query.source && contract.parties[1].endpoint == query.target;
    const bool backward = contract.parties[0].endpoint == query.target && contract.parties[1].endpoint == query.source;
    if (!forward && !backward) {
      continue;
    }
    if (contract.state != model::ContractState::Consented) {
      verdict.first_failure = "contract not consented";
      continue;
    }
    if (!contract.consents[0].has_value() || !contract.consents[1].has_value()) {
      verdict.first_failure = "missing consent";
      continue;
    }
    const model::ConsentRecord& first = *contract.consents[0];
    const model::ConsentRecord& second = *contract.consents[1];
    if (first.terms_digest != second.terms_digest || first.terms_digest != contract.terms_digest) {
      verdict.first_failure = "consent digest mismatch";
      continue;
    }
    if (first.decision != model::ConsentDecision::Accepted || second.decision != model::ConsentDecision::Accepted) {
      verdict.first_failure = "consent refused";
      continue;
    }
    bool bindings_current = true;
    for (std::size_t side = 0; side < model::kPartyCount; ++side) {
      const model::ClusterRecord* cluster = cluster_of(registry, contract.parties[side].endpoint);
      const model::ConsentRecord& consent = side == 0 ? first : second;
      if (cluster == nullptr || consent.incarnation != cluster->incarnation ||
          consent.generation != cluster->generation || consent.policy_generation != cluster->policy_generation ||
          consent.cluster != cluster->id) {
        bindings_current = false;
      }
    }
    if (!bindings_current) {
      verdict.first_failure = "consent bound to a superseded identity";
      continue;
    }
    found_contract = true;
    verdict.contract = contract.id;

    for (const auto& grant_entry : registry.grants()) {
      const model::GrantRecord& grant = grant_entry.second;
      if (grant.contract != contract.id) {
        continue;
      }
      if (grant.state != model::GrantState::Committed && grant.state != model::GrantState::Active) {
        continue;
      }
      if (!grant.acknowledged[0] || !grant.acknowledged[1]) {
        continue;
      }
      if (grant.terms_digest != contract.terms_digest) {
        continue;
      }
      if (grant.coordinator_term != view.term || grant.coordinator != view.incarnation) {
        continue;
      }
      bool bound = true;
      for (std::size_t side = 0; side < model::kPartyCount; ++side) {
        const model::ClusterRecord* cluster = cluster_of(registry, contract.parties[side].endpoint);
        if (cluster == nullptr || grant.incarnations[side] != cluster->incarnation ||
            grant.generations[side] != cluster->generation || grant.policies[side] != cluster->policy_generation) {
          bound = false;
        }
      }
      if (!bound) {
        continue;
      }
      if (grant.valid_until < view.now) {
        continue;
      }
      if (query.requested_capacity > grant.capacity) {
        continue;
      }
      verdict.authorized = true;
      verdict.degraded = degraded_only;
      verdict.grant = grant.id;
      return verdict;
    }
    verdict.first_failure = "no usable grant";
  }
  if (!found_contract) {
    verdict.first_failure = "no contract";
  }
  return verdict;
}

}  // namespace icf::test
