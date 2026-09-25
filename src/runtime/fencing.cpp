#include "icf/runtime/fencing.hpp"

#include <string>

#include "icf/core/limits.hpp"
#include "icf/runtime/audit.hpp"

namespace icf::runtime {
namespace {

// Returns the endpoint record's cluster so the caller can update the reservation counters.
void release_reservation(model::Registry& registry, model::ReservationRecord& reservation, Timestamp at,
                         FenceOutcome& outcome) {
  if (reservation.released) {
    ++outcome.already_fenced;
    return;
  }
  reservation.released = true;
  reservation.released_at = at;
  reservation.provenance = model::Provenance{};
  reservation.provenance.source = model::EvidenceSource::DerivedFromTopology;
  reservation.provenance.verification = model::VerificationState::Verified;
  reservation.provenance.observed_at = at;
  ++outcome.reservations_released;
  outcome.capacity_released += reservation.amount.value();
  const auto it = registry.reservations().find(reservation.id);
  if (it != registry.reservations().end()) {
    it->second = reservation;
  }

  // Return the capacity to the endpoint that held it.
  for (auto& cluster_entry : registry.clusters()) {
    model::ClusterRecord& cluster = cluster_entry.second;
    for (model::EndpointRecord& endpoint : cluster.endpoints) {
      if (endpoint.id != reservation.endpoint) {
        continue;
      }
      if (reservation.amount <= endpoint.reserved) {
        endpoint.reserved = endpoint.reserved.value() >= reservation.amount.value()
                                ? CapacityUnits(endpoint.reserved.value() - reservation.amount.value())
                                : CapacityUnits{};
      } else {
        endpoint.reserved = CapacityUnits{};
      }
      endpoint.provenance.observed_at = at;
      break;
    }
  }
}

}  // namespace

Result<FenceOutcome> apply_fence_plan(model::Registry& registry, const model::FencePlan& plan, Timestamp at,
                                      std::string actor) {
  FenceOutcome outcome;
  for (const model::FenceAction& action : plan.actions) {
    switch (action.target) {
      case model::FenceTarget::Grant: {
        model::GrantRecord* grant = registry.find_grant(action.grant);
        if (grant == nullptr) {
          ++outcome.already_fenced;
          continue;
        }
        if (grant->state == model::GrantState::Fenced || grant->state == model::GrantState::Aborted ||
            grant->state == model::GrantState::Withdrawn) {
          ++outcome.already_fenced;
          continue;
        }
        grant->state = model::GrantState::Fenced;
        grant->note = std::string("fenced by ") + to_string(plan.trigger);
        grant->provenance = model::Provenance{};
        grant->provenance.source = model::EvidenceSource::DerivedFromTopology;
        grant->provenance.verification = model::VerificationState::Verified;
        grant->provenance.observed_at = at;
        if (grant->revision.increment()) {
          // revision advances so that observers can order the fencing against other updates
        }
        ++outcome.grants_fenced;
        const Status audited = append_audit(registry, at, actor, "fence-grant",
                                            std::string("grant=") + grant->id.to_string(), Outcome::Fenced,
                                            std::string(to_string(plan.trigger)));
        if (!audited) {
          return audited;
        }
        break;
      }
      case model::FenceTarget::Contract: {
        model::ContractRecord* contract = registry.find_contract(action.contract);
        if (contract == nullptr) {
          continue;
        }
        if (contract->state == model::ContractState::Withdrawn || contract->state == model::ContractState::Fenced) {
          ++outcome.already_fenced;
          continue;
        }
        contract->state = plan.trigger == model::FenceTrigger::ClusterWithdrawal ? model::ContractState::Withdrawn
                                                                                : model::ContractState::Fenced;
        contract->updated_at = at;
        if (contract->revision.increment()) {
          // revision advances so ordering is observable
        }
        ++outcome.contracts_fenced;
        const Status audited = append_audit(registry, at, actor, "fence-contract",
                                            std::string("contract=") + contract->id.to_string(), Outcome::Fenced,
                                            std::string(to_string(plan.trigger)));
        if (!audited) {
          return audited;
        }
        break;
      }
      case model::FenceTarget::Reservation: {
        const auto it = registry.reservations().find(action.reservation);
        if (it == registry.reservations().end()) {
          ++outcome.already_fenced;
          continue;
        }
        model::ReservationRecord reservation = it->second;
        release_reservation(registry, reservation, at, outcome);
        break;
      }
    }
  }
  return outcome;
}

Result<FenceOutcome> fence_recovered_state(model::Registry& registry, Timestamp at, std::string actor,
                                           const IncarnationId& previous_incarnation, Term term) {
  model::FencePlan plan;
  plan.trigger = model::FenceTrigger::CoordinatorReincarnation;
  plan.previous_incarnation = previous_incarnation;
  plan.term = term;
  plan.view_digest = registry.digest();
  for (const auto& entry : registry.grants()) {
    const model::GrantRecord& grant = entry.second;
    if (grant.state == model::GrantState::Fenced || grant.state == model::GrantState::Aborted ||
        grant.state == model::GrantState::Expired || grant.state == model::GrantState::Withdrawn) {
      continue;
    }
    model::FenceAction action;
    action.target = model::FenceTarget::Grant;
    action.grant = grant.id;
    action.contract = grant.contract;
    action.reason = model::ReasonCode::EvidenceRecoveredFromStore;
    plan.actions.push_back(action);
  }
  for (const auto& entry : registry.reservations()) {
    const model::ReservationRecord& reservation = entry.second;
    if (reservation.released) {
      continue;
    }
    model::FenceAction action;
    action.target = model::FenceTarget::Reservation;
    action.grant = reservation.grant;
    action.reservation = reservation.id;
    action.reason = model::ReasonCode::EvidenceRecoveredFromStore;
    plan.actions.push_back(action);
  }
  plan.detail = "dynamic evidence recovered from the store is historical and is fenced until revalidated";
  return apply_fence_plan(registry, plan, at, std::move(actor));
}

}  // namespace icf::runtime
