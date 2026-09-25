// Inter-Cluster Fabric - the authoritative model.
//
// The registry is a deterministic, ordered container. Two coordinators that receive the same
// set of accepted updates in any order converge on the same digest, because every mutation is
// a total function of (current record, incoming update) and every container is key-ordered.
#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "icf/core/bytes.hpp"
#include "icf/core/hash.hpp"
#include "icf/model/records.hpp"

namespace icf::model {

struct RegistryCounts {
  std::size_t clusters = 0;
  std::size_t endpoints = 0;
  std::size_t links = 0;
  std::size_t paths = 0;
  std::size_t contracts = 0;
  std::size_t grants = 0;
  std::size_t reservations = 0;
  std::size_t policies = 0;
  std::size_t audit = 0;
};

class Registry {
 public:
  Registry() = default;

  // ---- clusters ---------------------------------------------------------------
  [[nodiscard]] const ClusterRecord* find_cluster(const ClusterId& id) const;
  [[nodiscard]] ClusterRecord* find_cluster(const ClusterId& id);
  [[nodiscard]] const EndpointRecord* find_endpoint(const EndpointId& id) const;
  [[nodiscard]] const std::map<ClusterId, ClusterRecord>& clusters() const noexcept { return clusters_; }
  [[nodiscard]] std::map<ClusterId, ClusterRecord>& clusters() noexcept { return clusters_; }
  Status put_cluster(ClusterRecord record);
  Status erase_cluster(const ClusterId& id);

  // ---- links and paths ---------------------------------------------------------
  [[nodiscard]] const LinkRecord* find_link(const EdgeId& id) const;
  [[nodiscard]] const std::map<EdgeId, LinkRecord>& links() const noexcept { return links_; }
  [[nodiscard]] std::map<EdgeId, LinkRecord>& links() noexcept { return links_; }
  Status put_link(LinkRecord record);
  Status erase_link(const EdgeId& id);

  [[nodiscard]] const PathRecord* find_path(const PathId& id) const;
  [[nodiscard]] const std::map<PathId, PathRecord>& paths() const noexcept { return paths_; }
  [[nodiscard]] std::map<PathId, PathRecord>& paths() noexcept { return paths_; }
  Status put_path(PathRecord record);
  Status erase_path(const PathId& id);
  // Recomputes path state from the current link states. Paths are derived evidence, so they
  // are always a pure function of the links they traverse.
  void recompute_path_states();

  // ---- policy ------------------------------------------------------------------
  [[nodiscard]] const std::map<std::string, PolicyRule>& policies() const noexcept { return policies_; }
  [[nodiscard]] std::map<std::string, PolicyRule>& policies() noexcept { return policies_; }
  Status put_policy(PolicyRule rule);
  Status erase_policy(const std::string& id);

  // ---- contracts, grants, reservations -----------------------------------------
  [[nodiscard]] const ContractRecord* find_contract(const ContractId& id) const;
  [[nodiscard]] ContractRecord* find_contract(const ContractId& id);
  [[nodiscard]] const std::map<ContractId, ContractRecord>& contracts() const noexcept { return contracts_; }
  [[nodiscard]] std::map<ContractId, ContractRecord>& contracts() noexcept { return contracts_; }
  Status put_contract(ContractRecord record);
  Status erase_contract(const ContractId& id);

  [[nodiscard]] const GrantRecord* find_grant(const GrantId& id) const;
  [[nodiscard]] GrantRecord* find_grant(const GrantId& id);
  [[nodiscard]] const std::map<GrantId, GrantRecord>& grants() const noexcept { return grants_; }
  [[nodiscard]] std::map<GrantId, GrantRecord>& grants() noexcept { return grants_; }
  Status put_grant(GrantRecord record);
  Status erase_grant(const GrantId& id);

  [[nodiscard]] const ReservationRecord* find_reservation(const ReservationId& id) const;
  [[nodiscard]] const std::map<ReservationId, ReservationRecord>& reservations() const noexcept {
    return reservations_;
  }
  [[nodiscard]] std::map<ReservationId, ReservationRecord>& reservations() noexcept { return reservations_; }
  Status put_reservation(ReservationRecord record);

  // ---- audit -------------------------------------------------------------------
  [[nodiscard]] const std::vector<AuditRecord>& audit() const noexcept { return audit_; }
  [[nodiscard]] std::vector<AuditRecord>& audit() noexcept { return audit_; }
  Status append_audit(AuditRecord record);

  // ---- derived -----------------------------------------------------------------
  [[nodiscard]] RegistryCounts counts() const noexcept;
  [[nodiscard]] Digest digest() const;
  [[nodiscard]] Status validate() const;
  void clear();

  // Capacity accounting helpers. All arithmetic is checked.
  [[nodiscard]] Result<CapacityUnits> endpoint_reserved(const EndpointId& id) const;
  [[nodiscard]] Result<CapacityUnits> link_reserved(const EdgeId& id) const;

 private:
  std::map<ClusterId, ClusterRecord> clusters_;
  std::map<EdgeId, LinkRecord> links_;
  std::map<PathId, PathRecord> paths_;
  std::map<std::string, PolicyRule> policies_;
  std::map<ContractId, ContractRecord> contracts_;
  std::map<GrantId, GrantRecord> grants_;
  std::map<ReservationId, ReservationRecord> reservations_;
  std::vector<AuditRecord> audit_;
};

// ---- canonical encoding -------------------------------------------------------
// Used for the model digest, for snapshots, and for the record bodies of wire messages.
void encode_cluster(const ClusterRecord& record, ByteWriter& writer);
[[nodiscard]] Result<ClusterRecord> decode_cluster(ByteReader& reader);
void encode_link(const LinkRecord& record, ByteWriter& writer);
[[nodiscard]] Result<LinkRecord> decode_link(ByteReader& reader);
void encode_path(const PathRecord& record, ByteWriter& writer);
[[nodiscard]] Result<PathRecord> decode_path(ByteReader& reader);
void encode_policy(const PolicyRule& record, ByteWriter& writer);
[[nodiscard]] Result<PolicyRule> decode_policy(ByteReader& reader);
void encode_contract(const ContractRecord& record, ByteWriter& writer);
[[nodiscard]] Result<ContractRecord> decode_contract(ByteReader& reader);
void encode_grant(const GrantRecord& record, ByteWriter& writer);
[[nodiscard]] Result<GrantRecord> decode_grant(ByteReader& reader);
void encode_reservation(const ReservationRecord& record, ByteWriter& writer);
[[nodiscard]] Result<ReservationRecord> decode_reservation(ByteReader& reader);
void encode_audit(const AuditRecord& record, ByteWriter& writer);
[[nodiscard]] Result<AuditRecord> decode_audit(ByteReader& reader);

// The audit trail is included in snapshots but excluded from the authorization digest:
// digest() covers exactly the state that can authorize connectivity.
void encode_registry(const Registry& registry, ByteWriter& writer, bool include_audit);
[[nodiscard]] Result<Registry> decode_registry(ByteReader& reader);
inline constexpr std::uint16_t kModelEncodingVersion = 1;

}  // namespace icf::model
