#include "icf/model/registry.hpp"

#include <algorithm>

#include "icf/core/checked.hpp"
#include "icf/core/limits.hpp"

namespace icf::model {
namespace {

// The key is taken by value and the record by value: every caller copies the identity into a
// local first, so the key can never be read from a record that has already been moved from.
template <class Map, class Key, class Record>
Status insert_bounded(Map& map, Key key, Record record, std::size_t bound, const char* what) {
  const auto existing = map.find(key);
  if (existing == map.end() && map.size() >= bound) {
    return Status::make(Outcome::CapacityExceeded, std::string("too many ") + what + " records");
  }
  map[key] = std::move(record);
  return Status::ok();
}

}  // namespace

const ClusterRecord* Registry::find_cluster(const ClusterId& id) const {
  const auto it = clusters_.find(id);
  return it == clusters_.end() ? nullptr : &it->second;
}

ClusterRecord* Registry::find_cluster(const ClusterId& id) {
  const auto it = clusters_.find(id);
  return it == clusters_.end() ? nullptr : &it->second;
}

const EndpointRecord* Registry::find_endpoint(const EndpointId& id) const {
  for (const auto& entry : clusters_) {
    const auto it = std::lower_bound(entry.second.endpoints.begin(), entry.second.endpoints.end(), id,
                                     [](const EndpointRecord& record, const EndpointId& value) {
                                       return record.id < value;
                                     });
    if (it != entry.second.endpoints.end() && it->id == id) {
      return &(*it);
    }
  }
  return nullptr;
}

Status Registry::put_cluster(ClusterRecord record) {
  if (record.id.empty()) {
    return invalid("cluster record requires an identity");
  }
  if (record.domain.empty()) {
    return invalid("cluster record requires an authority domain");
  }
  if (record.endpoints.size() > limits::kMaxEndpointsPerCluster) {
    return Status::make(Outcome::CapacityExceeded, "cluster declares too many endpoints");
  }
  std::sort(record.endpoints.begin(), record.endpoints.end(),
            [](const EndpointRecord& a, const EndpointRecord& b) { return a.id < b.id; });
  for (const EndpointRecord& endpoint : record.endpoints) {
    if (endpoint.cluster != record.id) {
      return invalid("endpoint scope is bound to a different cluster identity");
    }
    if (endpoint.reserved > endpoint.capacity) {
      return Status::make(Outcome::CapacityExceeded, "endpoint reservations exceed declared capacity");
    }
  }
  for (std::size_t i = 1; i < record.endpoints.size(); ++i) {
    if (record.endpoints[i - 1].id == record.endpoints[i].id) {
      return Status::make(Outcome::AlreadyExists, "cluster declares a duplicate endpoint identity");
    }
  }
  const ClusterId key = record.id;
  return insert_bounded(clusters_, key, std::move(record), limits::kMaxClusters, "cluster");
}

Status Registry::erase_cluster(const ClusterId& id) {
  const auto it = clusters_.find(id);
  if (it == clusters_.end()) {
    return not_found("cluster is not registered");
  }
  clusters_.erase(it);
  return Status::ok();
}

const LinkRecord* Registry::find_link(const EdgeId& id) const {
  const auto it = links_.find(id);
  return it == links_.end() ? nullptr : &it->second;
}

Status Registry::put_link(LinkRecord record) {
  if (record.id.empty() || record.a.empty() || record.b.empty()) {
    return invalid("link record requires an identity and two endpoints");
  }
  if (record.a == record.b) {
    return invalid("a link must join two distinct endpoints");
  }
  if (record.reserved > record.capacity) {
    return Status::make(Outcome::CapacityExceeded, "link reservations exceed declared capacity");
  }
  const EdgeId key = record.id;
  return insert_bounded(links_, key, std::move(record), limits::kMaxEdges, "link");
}

Status Registry::erase_link(const EdgeId& id) {
  const auto it = links_.find(id);
  if (it == links_.end()) {
    return not_found("link is not registered");
  }
  links_.erase(it);
  return Status::ok();
}

const PathRecord* Registry::find_path(const PathId& id) const {
  const auto it = paths_.find(id);
  return it == paths_.end() ? nullptr : &it->second;
}

Status Registry::put_path(PathRecord record) {
  if (record.id.empty() || record.a.empty() || record.b.empty()) {
    return invalid("path record requires an identity and two endpoints");
  }
  if (record.hops.empty()) {
    return invalid("path record requires at least one hop");
  }
  if (record.hops.size() > limits::kMaxPathHops) {
    return Status::make(Outcome::CapacityExceeded, "path declares too many hops");
  }
  const PathId key = record.id;
  return insert_bounded(paths_, key, std::move(record), limits::kMaxPaths, "path");
}

Status Registry::erase_path(const PathId& id) {
  const auto it = paths_.find(id);
  if (it == paths_.end()) {
    return not_found("path is not registered");
  }
  paths_.erase(it);
  return Status::ok();
}

void Registry::recompute_path_states() {
  for (auto& entry : paths_) {
    PathRecord& path = entry.second;
    PathState state = PathState::Up;
    CapacityUnits bottleneck;
    bool first = true;
    bool unsupported = false;
    for (const EdgeId& hop : path.hops) {
      const LinkRecord* link = find_link(hop);
      if (link == nullptr) {
        state = PathState::Unknown;
        break;
      }
      if (!link_kind_supported(link->kind)) {
        unsupported = true;
        state = PathState::Down;
        break;
      }
      switch (link->state) {
        case LinkState::Down:
          state = PathState::Down;
          break;
        case LinkState::Unknown:
          if (state != PathState::Down) {
            state = PathState::Unknown;
          }
          break;
        case LinkState::Degraded:
          if (state != PathState::Down && state != PathState::Unknown) {
            state = PathState::Degraded;
          }
          break;
        case LinkState::Unsupported:
          unsupported = true;
          state = PathState::Down;
          break;
        case LinkState::Up:
          break;
      }
      if (state == PathState::Down) {
        break;
      }
      if (first || link->capacity < bottleneck) {
        bottleneck = link->capacity;
        first = false;
      }
    }
    path.contains_unsupported_edge = unsupported;
    path.bottleneck = first ? CapacityUnits{} : bottleneck;
    path.state = state;
  }
}

Status Registry::put_policy(PolicyRule rule) {
  if (rule.id.empty() || rule.id.size() > limits::kMaxNameLength) {
    return invalid("policy rule requires a bounded identity");
  }
  if (rule.owner.empty()) {
    return invalid("policy rule requires an owning authority domain");
  }
  const std::string key = rule.id;
  return insert_bounded(policies_, key, std::move(rule), limits::kMaxPolicyRules, "policy");
}

Status Registry::erase_policy(const std::string& id) {
  const auto it = policies_.find(id);
  if (it == policies_.end()) {
    return not_found("policy rule is not registered");
  }
  policies_.erase(it);
  return Status::ok();
}

const ContractRecord* Registry::find_contract(const ContractId& id) const {
  const auto it = contracts_.find(id);
  return it == contracts_.end() ? nullptr : &it->second;
}

ContractRecord* Registry::find_contract(const ContractId& id) {
  const auto it = contracts_.find(id);
  return it == contracts_.end() ? nullptr : &it->second;
}

Status Registry::put_contract(ContractRecord record) {
  if (record.id.is_nil()) {
    return invalid("contract requires an identity");
  }
  if (record.parties[0].cluster.empty() || record.parties[1].cluster.empty()) {
    return invalid("contract requires two cluster identities");
  }
  if (record.parties[0].cluster == record.parties[1].cluster) {
    return invalid("contract must join two distinct clusters");
  }
  if (record.capacity.value() > limits::kMaxCapacity) {
    return Status::make(Outcome::Overflow, "contract capacity exceeds the maximum");
  }
  const ContractId key = record.id;
  return insert_bounded(contracts_, key, std::move(record), limits::kMaxContracts, "contract");
}

Status Registry::erase_contract(const ContractId& id) {
  const auto it = contracts_.find(id);
  if (it == contracts_.end()) {
    return not_found("contract is not registered");
  }
  contracts_.erase(it);
  return Status::ok();
}

const GrantRecord* Registry::find_grant(const GrantId& id) const {
  const auto it = grants_.find(id);
  return it == grants_.end() ? nullptr : &it->second;
}

GrantRecord* Registry::find_grant(const GrantId& id) {
  const auto it = grants_.find(id);
  return it == grants_.end() ? nullptr : &it->second;
}

Status Registry::put_grant(GrantRecord record) {
  if (record.id.is_nil()) {
    return invalid("grant requires an identity");
  }
  if (record.contract.is_nil()) {
    return invalid("grant requires a contract");
  }
  if (record.capacity.value() > limits::kMaxCapacity) {
    return Status::make(Outcome::Overflow, "grant capacity exceeds the maximum");
  }
  const GrantId key = record.id;
  return insert_bounded(grants_, key, std::move(record), limits::kMaxGrants, "grant");
}

Status Registry::erase_grant(const GrantId& id) {
  const auto it = grants_.find(id);
  if (grants_.end() == it) {
    return not_found("grant is not registered");
  }
  grants_.erase(it);
  return Status::ok();
}

const ReservationRecord* Registry::find_reservation(const ReservationId& id) const {
  const auto it = reservations_.find(id);
  return it == reservations_.end() ? nullptr : &it->second;
}

Status Registry::put_reservation(ReservationRecord record) {
  if (record.id.is_nil()) {
    return invalid("reservation requires an identity");
  }
  const ReservationId key = record.id;
  return insert_bounded(reservations_, key, std::move(record), limits::kMaxReservations, "reservation");
}

Status Registry::append_audit(AuditRecord record) {
  if (audit_.size() >= limits::kMaxAuditRecords) {
    return Status::make(Outcome::CapacityExceeded, "audit trail is at its configured bound");
  }
  if (!audit_.empty()) {
    const Sequence expected = audit_.back().sequence.next().value();
    if (record.sequence != expected) {
      return invalid("audit sequence is not contiguous");
    }
  }
  audit_.push_back(std::move(record));
  return Status::ok();
}

RegistryCounts Registry::counts() const noexcept {
  RegistryCounts counts;
  counts.clusters = clusters_.size();
  for (const auto& entry : clusters_) {
    counts.endpoints += entry.second.endpoints.size();
  }
  counts.links = links_.size();
  counts.paths = paths_.size();
  counts.contracts = contracts_.size();
  counts.grants = grants_.size();
  counts.reservations = reservations_.size();
  counts.policies = policies_.size();
  counts.audit = audit_.size();
  return counts;
}

Digest Registry::digest() const {
  ByteWriter writer;
  encode_registry(*this, writer, false);
  return Sha256::hash(writer.data());
}

Status Registry::validate() const {
  std::size_t endpoint_total = 0;
  for (const auto& entry : clusters_) {
    const ClusterRecord& cluster = entry.second;
    if (cluster.id != entry.first) {
      return invalid("cluster map key does not match the record identity");
    }
    endpoint_total += cluster.endpoints.size();
    if (endpoint_total > limits::kMaxEndpointsTotal) {
      return Status::make(Outcome::CapacityExceeded, "endpoint total exceeds the configured bound");
    }
    for (const EndpointRecord& endpoint : cluster.endpoints) {
      if (endpoint.id.empty()) {
        return invalid("endpoint record has an empty identity");
      }
      if (endpoint.cluster != cluster.id) {
        return invalid("endpoint record is bound to a different cluster");
      }
      if (endpoint.reserved > endpoint.capacity) {
        return Status::make(Outcome::CapacityExceeded, "endpoint reservations exceed capacity");
      }
    }
  }
  for (const auto& entry : links_) {
    const LinkRecord& link = entry.second;
    if (link.id != entry.first) {
      return invalid("link map key does not match the record identity");
    }
    if (find_endpoint(link.a) == nullptr || find_endpoint(link.b) == nullptr) {
      return invalid("link references an endpoint that is not registered");
    }
    if (link.reserved > link.capacity) {
      return Status::make(Outcome::CapacityExceeded, "link reservations exceed capacity");
    }
  }
  for (const auto& entry : paths_) {
    const PathRecord& path = entry.second;
    if (path.id != entry.first) {
      return invalid("path map key does not match the record identity");
    }
    for (const EdgeId& hop : path.hops) {
      if (find_link(hop) == nullptr) {
        return invalid("path references a link that is not registered");
      }
    }
  }
  for (const auto& entry : policies_) {
    if (entry.second.id != entry.first) {
      return invalid("policy map key does not match the rule identity");
    }
  }
  for (const auto& entry : contracts_) {
    const ContractRecord& contract = entry.second;
    if (contract.id != entry.first) {
      return invalid("contract map key does not match the record identity");
    }
    for (const PartyRef& party : contract.parties) {
      const ClusterRecord* cluster = find_cluster(party.cluster);
      if (cluster == nullptr) {
        return invalid("contract references a cluster that is not registered");
      }
      if (find_endpoint(party.endpoint) == nullptr) {
        return invalid("contract references an endpoint that is not registered");
      }
    }
  }
  for (const auto& entry : grants_) {
    const GrantRecord& grant = entry.second;
    if (grant.id != entry.first) {
      return invalid("grant map key does not match the record identity");
    }
    if (find_contract(grant.contract) == nullptr) {
      return invalid("grant references a contract that is not registered");
    }
    if (grant.valid_until < grant.issued_at) {
      return invalid("grant validity window ends before it begins");
    }
  }
  for (const auto& entry : reservations_) {
    const ReservationRecord& reservation = entry.second;
    if (reservation.id != entry.first) {
      return invalid("reservation map key does not match the record identity");
    }
    if (find_grant(reservation.grant) == nullptr) {
      return invalid("reservation references a grant that is not registered");
    }
    if (reservation.released && reservation.released_at < reservation.created_at) {
      return invalid("reservation was released before it was created");
    }
  }
  for (std::size_t i = 0; i < audit_.size(); ++i) {
    if (i > 0 && !(audit_[i - 1].sequence < audit_[i].sequence)) {
      return invalid("audit sequence is not strictly increasing");
    }
  }
  return Status::ok();
}

void Registry::clear() {
  clusters_.clear();
  links_.clear();
  paths_.clear();
  policies_.clear();
  contracts_.clear();
  grants_.clear();
  reservations_.clear();
  audit_.clear();
}

Result<CapacityUnits> Registry::endpoint_reserved(const EndpointId& id) const {
  const EndpointRecord* endpoint = find_endpoint(id);
  if (endpoint == nullptr) {
    return not_found("endpoint is not registered");
  }
  return endpoint->reserved;
}

Result<CapacityUnits> Registry::link_reserved(const EdgeId& id) const {
  const LinkRecord* link = find_link(id);
  if (link == nullptr) {
    return not_found("link is not registered");
  }
  return link->reserved;
}

}  // namespace icf::model
