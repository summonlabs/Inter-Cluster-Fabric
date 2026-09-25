#include "icf/runtime/engine.hpp"

#include <algorithm>

#include "icf/core/limits.hpp"
#include "icf/model/policy.hpp"
#include "icf/model/terms.hpp"

namespace icf::runtime {
namespace {

void add_reason(model::Decision& decision, model::ReasonCode code) {
  if (decision.reasons.size() >= limits::kMaxDecisionReasons) {
    return;
  }
  if (std::find(decision.reasons.begin(), decision.reasons.end(), code) == decision.reasons.end()) {
    decision.reasons.push_back(code);
  }
}

void finish(model::Decision& decision, Outcome outcome, std::string detail) {
  decision.outcome = outcome;
  decision.detail = std::move(detail);
}

// Returns the endpoint record together with the cluster it belongs to.
struct ResolvedEndpoint {
  const model::EndpointRecord* endpoint = nullptr;
  const model::ClusterRecord* cluster = nullptr;
};

ResolvedEndpoint resolve(const model::Registry& registry, const EndpointId& id) {
  ResolvedEndpoint result;
  for (const auto& entry : registry.clusters()) {
    const auto it = std::lower_bound(entry.second.endpoints.begin(), entry.second.endpoints.end(), id,
                                     [](const model::EndpointRecord& record, const EndpointId& value) {
                                       return record.id < value;
                                     });
    if (it != entry.second.endpoints.end() && it->id == id) {
      result.endpoint = &(*it);
      result.cluster = &entry.second;
      return result;
    }
  }
  return result;
}

Status check_cluster(const model::ClusterRecord& cluster, model::Decision& decision) {
  switch (cluster.state) {
    case model::ClusterState::Unknown:
      add_reason(decision, model::ReasonCode::ResourceUnknown);
      add_reason(decision, model::ReasonCode::ClusterUnknown);
      return Status::make(Outcome::Unknown, "cluster state has not been established");
    case model::ClusterState::Suspended:
      add_reason(decision, model::ReasonCode::ClusterSuspended);
      return Status::make(Outcome::Refused, "cluster is administratively suspended");
    case model::ClusterState::Draining:
      add_reason(decision, model::ReasonCode::ClusterDraining);
      return Status::make(Outcome::Refused, "cluster is draining and accepts no new connectivity");
    case model::ClusterState::Retired:
      add_reason(decision, model::ReasonCode::ClusterRetired);
      return Status::make(Outcome::Fenced, "cluster identity is retired");
    case model::ClusterState::Active:
      break;
  }
  if (cluster.generation_conflict) {
    add_reason(decision, model::ReasonCode::ClusterGenerationConflict);
    return Status::make(Outcome::Conflicting,
                        "two updates claimed the same generation with different contents; the conflict is unresolved");
  }
  if (cluster.consent_withdrawn) {
    add_reason(decision, model::ReasonCode::ClusterConsentWithdrawn);
    return Status::make(Outcome::Refused, "cluster has withdrawn consent for cross-cluster connectivity");
  }
  return Status::ok();
}

Status check_endpoint(const model::EndpointRecord& endpoint, bool is_source, model::Decision& decision) {
  switch (endpoint.state) {
    case model::EndpointState::Unknown:
      add_reason(decision, model::ReasonCode::ResourceUnknown);
      return Status::make(Outcome::Unknown, "endpoint state has not been established");
    case model::EndpointState::Suspended:
      add_reason(decision, is_source ? model::ReasonCode::SourceEndpointSuspended
                                     : model::ReasonCode::TargetEndpointSuspended);
      return Status::make(Outcome::Refused, "endpoint scope is administratively suspended");
    case model::EndpointState::Draining:
      add_reason(decision, is_source ? model::ReasonCode::SourceEndpointSuspended
                                     : model::ReasonCode::TargetEndpointSuspended);
      return Status::make(Outcome::Refused, "endpoint scope is draining");
    case model::EndpointState::Retired:
      add_reason(decision, model::ReasonCode::ResourceUnknown);
      return Status::make(Outcome::Fenced, "endpoint scope is retired");
    case model::EndpointState::Active:
      break;
  }
  if (!endpoint.inter_cluster_allowed) {
    add_reason(decision, is_source ? model::ReasonCode::SourceEndpointRefused
                                   : model::ReasonCode::TargetEndpointRefused);
    return Status::make(Outcome::Refused, "endpoint scope does not accept inter-cluster connectivity");
  }
  return Status::ok();
}

const model::ContractRecord* find_contract_for(const model::Registry& registry, const EndpointId& source,
                                               const EndpointId& target) {
  for (const auto& entry : registry.contracts()) {
    const model::ContractRecord& contract = entry.second;
    const bool forward = contract.parties[0].endpoint == source && contract.parties[1].endpoint == target;
    const bool backward = contract.parties[0].endpoint == target && contract.parties[1].endpoint == source;
    if (forward || backward) {
      return &contract;
    }
  }
  return nullptr;
}

Status check_consents(const model::Registry& registry, const model::ContractRecord& contract,
                      model::Decision& decision) {
  if (contract.state == model::ContractState::Refused) {
    add_reason(decision, model::ReasonCode::ContractRefused);
    return Status::make(Outcome::Refused, "one authority domain refused the contract");
  }
  if (contract.state == model::ContractState::Withdrawn) {
    add_reason(decision, model::ReasonCode::ContractWithdrawn);
    return Status::make(Outcome::Fenced, "a party withdrew consent for the contract");
  }
  if (contract.state == model::ContractState::Fenced) {
    add_reason(decision, model::ReasonCode::ContractFenced);
    return Status::make(Outcome::Fenced, "the contract was fenced by a superseding change");
  }
  if (contract.state == model::ContractState::Expired) {
    add_reason(decision, model::ReasonCode::ContractExpired);
    return Status::make(Outcome::Expired, "the contract validity window elapsed");
  }
  if (!contract.both_consented()) {
    add_reason(decision, model::ReasonCode::ContractNotConsented);
    return Status::make(Outcome::Incomplete, "both authority domains have not consented to identical terms");
  }
  for (std::size_t index = 0; index < contract.consents.size(); ++index) {
    const model::ConsentRecord& consent = *contract.consents[index];
    if (consent.decision != model::ConsentDecision::Accepted) {
      add_reason(decision, model::ReasonCode::ContractNotConsented);
      return Status::make(Outcome::Refused, "a party refused the contract");
    }
    if (consent.terms_digest != contract.terms_digest) {
      add_reason(decision, model::ReasonCode::ConsentMismatch);
      return Status::make(Outcome::Conflicting,
                          "the recorded consents do not cover identical terms; one side consented to something else");
    }
    const model::PartyRef& party = contract.parties[index];
    const model::ClusterRecord* cluster = registry.find_cluster(party.cluster);
    if (cluster == nullptr) {
      add_reason(decision, model::ReasonCode::ClusterUnknown);
      return Status::make(Outcome::Unknown, "a contracting cluster is no longer registered");
    }
    if (consent.cluster != party.cluster || consent.endpoint != party.endpoint) {
      add_reason(decision, model::ReasonCode::ConsentMismatch);
      return Status::make(Outcome::Conflicting, "a consent record names a different party than the contract");
    }
    if (consent.incarnation != cluster->incarnation) {
      add_reason(decision, model::ReasonCode::IncarnationMismatch);
      return Status::make(Outcome::Stale, "a consent was issued by a superseded cluster incarnation");
    }
    if (consent.generation != cluster->generation) {
      add_reason(decision, model::ReasonCode::GenerationStale);
      return Status::make(Outcome::Stale, "a consent was issued at a superseded cluster generation");
    }
    if (consent.policy_generation != cluster->policy_generation) {
      add_reason(decision, model::ReasonCode::PolicyGenerationStale);
      return Status::make(Outcome::Stale, "a consent was issued under a superseded policy generation");
    }
  }
  return Status::ok();
}

Status check_grant(const model::Registry& registry, const model::ContractRecord& contract,
                   const model::DecisionQuery& query, const EngineView& view, model::Decision& decision) {
  const model::GrantRecord* selected = nullptr;
  for (const auto& entry : registry.grants()) {
    if (entry.second.contract != contract.id) {
      continue;
    }
    if (selected == nullptr || selected->issued_at < entry.second.issued_at ||
        (selected->issued_at == entry.second.issued_at && selected->id < entry.second.id)) {
      selected = &entry.second;
    }
  }
  if (selected == nullptr) {
    add_reason(decision, model::ReasonCode::NoGrant);
    return Status::make(Outcome::Incomplete, "no grant has been issued for this contract");
  }
  decision.grant = selected->id;
  decision.capacity = selected->capacity;
  decision.terms_digest = selected->terms_digest;

  switch (selected->state) {
    case model::GrantState::Preparing:
    case model::GrantState::Prepared:
      add_reason(decision, model::ReasonCode::GrantNotCommitted);
      return Status::make(Outcome::Incomplete, "the grant has not been committed by both parties");
    case model::GrantState::Indeterminate:
      add_reason(decision, model::ReasonCode::GrantIndeterminate);
      return Status::make(Outcome::Indeterminate,
                          "the grant commit acknowledgement is unresolved; the grant is not usable");
    case model::GrantState::Aborted:
    case model::GrantState::Fenced:
    case model::GrantState::Withdrawn:
      add_reason(decision, model::ReasonCode::GrantFenced);
      return Status::make(Outcome::Fenced, "the grant was fenced or aborted");
    case model::GrantState::Expired:
      add_reason(decision, model::ReasonCode::GrantExpired);
      return Status::make(Outcome::Expired, "the grant validity window elapsed");
    case model::GrantState::Committed:
    case model::GrantState::Active:
      break;
  }
  if (!selected->both_acknowledged()) {
    add_reason(decision, model::ReasonCode::GrantNotAcknowledged);
    return Status::make(Outcome::Incomplete, "a party has not acknowledged the committed grant");
  }
  if (selected->coordinator_term != view.term || selected->coordinator != view.incarnation) {
    add_reason(decision, model::ReasonCode::GrantTermMismatch);
    return Status::make(Outcome::Fenced, "the grant was issued under a superseded coordinator term");
  }
  if (selected->terms_digest != contract.terms_digest) {
    add_reason(decision, model::ReasonCode::ConsentMismatch);
    return Status::make(Outcome::Conflicting, "the grant does not cover the contract terms it names");
  }
  for (std::size_t index = 0; index < model::kPartyCount; ++index) {
    const model::ClusterRecord* cluster = registry.find_cluster(contract.parties[index].cluster);
    if (cluster == nullptr) {
      add_reason(decision, model::ReasonCode::ClusterUnknown);
      return Status::make(Outcome::Unknown, "a bound cluster is no longer registered");
    }
    if (selected->incarnations[index] != cluster->incarnation) {
      add_reason(decision, model::ReasonCode::IncarnationMismatch);
      return Status::make(Outcome::Fenced, "the grant is bound to a superseded cluster incarnation");
    }
    if (selected->generations[index] != cluster->generation) {
      add_reason(decision, model::ReasonCode::GenerationStale);
      return Status::make(Outcome::Stale, "the grant is bound to a superseded cluster generation");
    }
    if (selected->policies[index] != cluster->policy_generation) {
      add_reason(decision, model::ReasonCode::PolicyGenerationStale);
      return Status::make(Outcome::Stale, "the grant is bound to a superseded policy generation");
    }
  }
  if (view.now.unix_nanos() > selected->valid_until.unix_nanos()) {
    add_reason(decision, model::ReasonCode::GrantExpired);
    return Status::make(Outcome::Expired, "the grant validity window elapsed");
  }
  if (query.requested_capacity > selected->capacity) {
    add_reason(decision, model::ReasonCode::GrantCapacityExceeded);
    return Status::make(Outcome::CapacityExceeded, "the requested capacity exceeds the granted capacity");
  }
  return Status::ok();
}

struct PathEvaluation {
  Status status;
  bool degraded = false;
  std::vector<PathId> paths;
  std::vector<EdgeId> edges;
};

PathEvaluation evaluate_paths(const model::Registry& registry, const EndpointId& source, const EndpointId& target) {
  PathEvaluation evaluation;
  evaluation.status = Status::make(Outcome::Partitioned, "no path is registered between the endpoint scopes");
  bool saw_up = false;
  bool saw_degraded = false;
  bool saw_unknown = false;
  bool saw_unsupported = false;
  for (const auto& entry : registry.paths()) {
    const model::PathRecord& path = entry.second;
    const bool forward = path.a == source && path.b == target;
    const bool backward = path.a == target && path.b == source;
    if (!forward && !backward) {
      continue;
    }
    if (path.contains_unsupported_edge) {
      saw_unsupported = true;
      continue;
    }
    switch (path.state) {
      case model::PathState::Up:
        saw_up = true;
        if (evaluation.paths.size() < limits::kMaxDecisionPaths) {
          evaluation.paths.push_back(path.id);
          for (const EdgeId& hop : path.hops) {
            if (std::find(evaluation.edges.begin(), evaluation.edges.end(), hop) == evaluation.edges.end()) {
              evaluation.edges.push_back(hop);
            }
          }
        }
        break;
      case model::PathState::Degraded:
        saw_degraded = true;
        break;
      case model::PathState::Unknown:
        saw_unknown = true;
        break;
      case model::PathState::Down:
        break;
    }
  }
  if (saw_up) {
    evaluation.status = Status::ok();
    return evaluation;
  }
  if (saw_degraded) {
    evaluation.degraded = true;
    evaluation.status = Status::ok();
    return evaluation;
  }
  if (saw_unknown) {
    evaluation.status = Status::make(Outcome::Unknown, "path state has not been established");
    return evaluation;
  }
  if (saw_unsupported) {
    evaluation.status = Status::make(Outcome::Unsupported,
                                     "every registered path uses a link kind this runtime does not drive");
    return evaluation;
  }
  evaluation.status = Status::make(Outcome::Partitioned, "every registered path is down");
  return evaluation;
}

}  // namespace

model::Decision decide(const model::Registry& registry, const model::DecisionQuery& query, const EngineView& view) {
  model::Decision decision;
  decision.decided_at = view.now;
  decision.term = view.term;
  decision.coordinator = view.incarnation;
  decision.view_digest = registry.digest();

  const ResolvedEndpoint source = resolve(registry, query.source);
  if (source.endpoint == nullptr) {
    add_reason(decision, model::ReasonCode::SourceEndpointNotRegistered);
    finish(decision, Outcome::NotFound, "source endpoint is not registered");
    return decision;
  }
  const ResolvedEndpoint target = resolve(registry, query.target);
  if (target.endpoint == nullptr) {
    add_reason(decision, model::ReasonCode::TargetEndpointNotRegistered);
    finish(decision, Outcome::NotFound, "target endpoint is not registered");
    return decision;
  }
  if (query.source == query.target) {
    add_reason(decision, model::ReasonCode::EndpointsAreIdentical);
    finish(decision, Outcome::Invalid, "source and target endpoint are the same scope");
    return decision;
  }
  decision.authorities[0] = source.cluster->domain;
  decision.authorities[1] = target.cluster->domain;

  Status status = check_cluster(*source.cluster, decision);
  if (!status) {
    finish(decision, status.outcome(), status.message());
    return decision;
  }
  status = check_cluster(*target.cluster, decision);
  if (!status) {
    finish(decision, status.outcome(), status.message());
    return decision;
  }
  status = check_endpoint(*source.endpoint, true, decision);
  if (!status) {
    finish(decision, status.outcome(), status.message());
    return decision;
  }
  status = check_endpoint(*target.endpoint, false, decision);
  if (!status) {
    finish(decision, status.outcome(), status.message());
    return decision;
  }
  if (query.expect_source_generation && query.source_generation != source.cluster->generation) {
    add_reason(decision, model::ReasonCode::GenerationStale);
    finish(decision, Outcome::Stale, "the source cluster generation does not match the caller's expectation");
    return decision;
  }
  if (query.expect_target_generation && query.target_generation != target.cluster->generation) {
    add_reason(decision, model::ReasonCode::GenerationStale);
    finish(decision, Outcome::Stale, "the target cluster generation does not match the caller's expectation");
    return decision;
  }

  const model::PolicyEvaluation policy =
      model::evaluate_policy(registry, *source.cluster, *target.cluster, query.source, query.target);
  switch (policy.decision) {
    case model::PolicyDecision::RefusedExplicitly:
      add_reason(decision, model::ReasonCode::PolicyRefused);
      finish(decision, Outcome::Refused, "an authority domain explicitly refuses this pair: " + policy.detail);
      return decision;
    case model::PolicyDecision::MissingAllowRule:
      add_reason(decision, model::ReasonCode::PolicyMissingAllow);
      finish(decision, Outcome::Unauthorized,
             "no allow rule covers this pair from every authority domain: " + policy.detail);
      return decision;
    case model::PolicyDecision::StaleGeneration:
      add_reason(decision, model::ReasonCode::PolicyStaleGeneration);
      finish(decision, Outcome::Stale, "matching policy rules belong to a superseded policy generation");
      return decision;
    case model::PolicyDecision::Unsupported:
      add_reason(decision, model::ReasonCode::ResourceUnsupported);
      finish(decision, Outcome::Unsupported, policy.detail);
      return decision;
    case model::PolicyDecision::Allowed:
      add_reason(decision, model::ReasonCode::PolicyAllowed);
      break;
  }

  PathEvaluation paths = evaluate_paths(registry, query.source, query.target);
  if (!paths.status) {
    switch (paths.status.outcome()) {
      case Outcome::Partitioned:
        add_reason(decision, model::ReasonCode::PathAbsent);
        break;
      case Outcome::Unknown:
        add_reason(decision, model::ReasonCode::LinkUnknown);
        break;
      case Outcome::Unsupported:
        add_reason(decision, model::ReasonCode::PathUnsupported);
        break;
      default:
        add_reason(decision, model::ReasonCode::PathDown);
        break;
    }
    finish(decision, paths.status.outcome(), paths.status.message());
    return decision;
  }

  // Several contracts may cover the same endpoint pair (for example an older one that was fenced
  // by a reincarnation and a newer one issued afterwards). The decision is authorized when any
  // contract with a usable grant exists; the order is deterministic (most recently updated first,
  // then by identity) so the same registry always produces the same answer.
  std::vector<const model::ContractRecord*> candidates;
  for (const auto& entry : registry.contracts()) {
    const model::ContractRecord& candidate = entry.second;
    const bool forward = candidate.parties[0].endpoint == query.source && candidate.parties[1].endpoint == query.target;
    const bool backward = candidate.parties[0].endpoint == query.target && candidate.parties[1].endpoint == query.source;
    if (forward || backward) {
      candidates.push_back(&candidate);
    }
  }
  if (candidates.empty()) {
    add_reason(decision, model::ReasonCode::NoContract);
    finish(decision, Outcome::Unauthorized, "no connectivity contract covers this endpoint pair");
    return decision;
  }
  std::sort(candidates.begin(), candidates.end(),
            [](const model::ContractRecord* left, const model::ContractRecord* right) {
              if (left->updated_at != right->updated_at) {
                return right->updated_at < left->updated_at;
              }
              return left->id < right->id;
            });
  std::optional<model::Decision> best_failure;
  bool authorized_candidate = false;
  for (const model::ContractRecord* candidate : candidates) {
    model::Decision trial = decision;
    trial.contract = candidate->id;
    trial.terms_digest = candidate->terms_digest;
    Status trial_status = check_consents(registry, *candidate, trial);
    if (!trial_status) {
      if (!best_failure.has_value()) {
        finish(trial, trial_status.outcome(), trial_status.message());
        best_failure = std::move(trial);
      }
      continue;
    }
    add_reason(trial, model::ReasonCode::AuthoritySatisfied);
    trial_status = check_grant(registry, *candidate, query, view, trial);
    if (!trial_status) {
      if (!best_failure.has_value()) {
        finish(trial, trial_status.outcome(), trial_status.message());
        best_failure = std::move(trial);
      }
      continue;
    }
    decision = std::move(trial);
    status = Status::ok();
    authorized_candidate = true;
    break;
  }
  if (!authorized_candidate) {
    if (best_failure.has_value()) {
      return best_failure.value();
    }
    // Unreachable for a non-empty candidate list: reported as indeterminate, never as success.
    add_reason(decision, model::ReasonCode::EvidenceIncomplete);
    finish(decision, Outcome::Indeterminate, "no contract could be evaluated for this endpoint pair");
    return decision;
  }

  decision.paths = std::move(paths.paths);
  decision.edges = std::move(paths.edges);
  decision.degraded = paths.degraded;
  if (paths.degraded) {
    if (!query.allow_degraded || !policy.allow_degraded || !source.endpoint->permits_degraded ||
        !target.endpoint->permits_degraded) {
      add_reason(decision, model::ReasonCode::PathNotPermittedDegraded);
      finish(decision, Outcome::Unauthorized,
             "only a degraded path exists and degraded connectivity is not permitted for this pair");
      return decision;
    }
    add_reason(decision, model::ReasonCode::PathDegraded);
    finish(decision, Outcome::DegradedAuthorized,
           "authorized, but only over a degraded path; the authorization is not a healthy-path grant");
    return decision;
  }
  finish(decision, Outcome::Ok, "connectivity is authorized by both authority domains");
  return decision;
}

model::FencePlan plan_fence(const model::Registry& registry, model::FenceTrigger trigger, const ClusterId& cluster,
                            const IncarnationId& new_incarnation, const IncarnationId& previous_incarnation,
                            const Generation& new_generation, Term term) {
  model::FencePlan plan;
  plan.trigger = trigger;
  plan.cluster = cluster;
  plan.incarnation = new_incarnation;
  plan.previous_incarnation = previous_incarnation;
  plan.generation = new_generation;
  plan.term = term;
  plan.view_digest = registry.digest();

  model::ReasonCode grant_reason = model::ReasonCode::GrantFenced;
  switch (trigger) {
    case model::FenceTrigger::ClusterReincarnation:
      grant_reason = model::ReasonCode::IncarnationMismatch;
      break;
    case model::FenceTrigger::ClusterWithdrawal:
      grant_reason = model::ReasonCode::ClusterConsentWithdrawn;
      break;
    case model::FenceTrigger::PolicyGenerationChange:
      grant_reason = model::ReasonCode::PolicyGenerationStale;
      break;
    case model::FenceTrigger::CoordinatorReincarnation:
      grant_reason = model::ReasonCode::GrantTermMismatch;
      break;
    case model::FenceTrigger::GrantRevocation:
      grant_reason = model::ReasonCode::GrantFenced;
      break;
    case model::FenceTrigger::LinkFailure:
      grant_reason = model::ReasonCode::PathDown;
      break;
    case model::FenceTrigger::GrantExpiry:
      grant_reason = model::ReasonCode::GrantExpired;
      break;
    case model::FenceTrigger::Manual:
      grant_reason = model::ReasonCode::GrantFenced;
      break;
  }

  for (const auto& entry : registry.contracts()) {
    const model::ContractRecord& contract = entry.second;
    const int side = contract.side_of(cluster);
    if (side < 0) {
      continue;
    }
    bool contract_affected = false;
    for (const auto& grant_entry : registry.grants()) {
      const model::GrantRecord& grant = grant_entry.second;
      if (grant.contract != contract.id) {
        continue;
      }
      if (grant.usable_state() || grant.state == model::GrantState::Prepared ||
          grant.state == model::GrantState::Preparing || grant.state == model::GrantState::Indeterminate) {
        model::FenceAction action;
        action.target = model::FenceTarget::Grant;
        action.grant = grant.id;
        action.contract = contract.id;
        action.reason = grant_reason;
        plan.actions.push_back(action);
        contract_affected = true;
      }
      for (const auto& reservation_entry : registry.reservations()) {
        const model::ReservationRecord& reservation = reservation_entry.second;
        if (reservation.grant != grant.id || reservation.released) {
          continue;
        }
        model::FenceAction action;
        action.target = model::FenceTarget::Reservation;
        action.grant = grant.id;
        action.contract = contract.id;
        action.reservation = reservation.id;
        action.reason = grant_reason;
        plan.actions.push_back(action);
      }
    }
    if (contract_affected && contract.state != model::ContractState::Withdrawn) {
      model::FenceAction action;
      action.target = model::FenceTarget::Contract;
      action.contract = contract.id;
      action.reason = grant_reason;
      plan.actions.push_back(action);
    }
    if (plan.actions.size() > limits::kMaxFencePlanEntries) {
      break;
    }
  }
  plan.detail = std::string("fence plan for ") + to_string(trigger) + " affecting cluster " + cluster.str();
  return plan;
}

model::FencePlan plan_coordinator_fence(const model::Registry& registry, const IncarnationId& previous_incarnation,
                                       Term term) {
  model::FencePlan plan;
  plan.trigger = model::FenceTrigger::CoordinatorReincarnation;
  plan.incarnation = IncarnationId{};
  plan.previous_incarnation = previous_incarnation;
  plan.term = term;
  plan.view_digest = registry.digest();
  for (const auto& entry : registry.grants()) {
    const model::GrantRecord& grant = entry.second;
    if (grant.state == model::GrantState::Fenced || grant.state == model::GrantState::Aborted ||
        grant.state == model::GrantState::Expired || grant.state == model::GrantState::Withdrawn) {
      continue;
    }
    if (!previous_incarnation.is_nil() && grant.coordinator != previous_incarnation) {
      continue;
    }
    model::FenceAction action;
    action.target = model::FenceTarget::Grant;
    action.grant = grant.id;
    action.contract = grant.contract;
    action.reason = model::ReasonCode::GrantTermMismatch;
    plan.actions.push_back(action);
    for (const auto& reservation_entry : registry.reservations()) {
      const model::ReservationRecord& reservation = reservation_entry.second;
      if (reservation.grant != grant.id || reservation.released) {
        continue;
      }
      model::FenceAction release;
      release.target = model::FenceTarget::Reservation;
      release.grant = grant.id;
      release.contract = grant.contract;
      release.reservation = reservation.id;
      release.reason = model::ReasonCode::GrantTermMismatch;
      plan.actions.push_back(release);
    }
  }
  plan.detail = "every grant issued by the previous coordinator incarnation is fenced";
  return plan;
}

}  // namespace icf::runtime
