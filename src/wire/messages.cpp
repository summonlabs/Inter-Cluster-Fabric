#include "icf/wire/messages.hpp"

#include <utility>

#include "icf/core/checked.hpp"
#include "icf/core/limits.hpp"

namespace icf::wire {
namespace {

Result<std::string> read_text(ByteReader& reader) { return reader.blob(limits::kMaxStringField); }

Status write_text(ByteWriter& writer, const std::string& value) {
  if (value.size() > limits::kMaxStringField) {
    return invalid("text field exceeds the maximum length");
  }
  writer.blob(value);
  return Status::ok();
}

template <class Name>
Status write_name(ByteWriter& writer, const Name& value) {
  writer.blob(value.str());
  return Status::ok();
}

template <class Name>
Result<Name> read_name(ByteReader& reader, std::size_t max_length) {
  Result<std::string> text = reader.blob(max_length);
  if (!text) {
    return text.status();
  }
  return Name::parse(text.value());
}

// Reads a name field that may be absent (an empty string). Semantic presence rules belong to the
// message handler, not to the decoder: an observer handshake legitimately carries no cluster.
template <class Name>
Result<Name> read_optional_name(ByteReader& reader, std::size_t max_length) {
  Result<std::string> text = reader.blob(max_length);
  if (!text) {
    return text.status();
  }
  if (text.value().empty()) {
    return Name{};
  }
  return Name::parse(text.value());
}

Result<Uuid> read_uuid(ByteReader& reader) { return reader.uuid(); }

void write_uuid(ByteWriter& writer, const Uuid& value) { writer.uuid(value); }

Result<std::uint64_t> read_counter(ByteReader& reader, std::uint64_t bound) {
  Result<std::uint64_t> value = reader.u64();
  if (!value) {
    return value.status();
  }
  if (value.value() > bound) {
    return Status::make(Outcome::Overflow, "counter exceeds the maximum permitted value");
  }
  return value.value();
}

template <class Enum>
Result<Enum> read_enum8(ByteReader& reader, std::uint8_t max_value) {
  Result<std::uint8_t> raw = reader.u8();
  if (!raw) {
    return raw.status();
  }
  if (raw.value() > max_value) {
    return invalid("enumeration value is out of range");
  }
  return static_cast<Enum>(raw.value());
}

Result<Outcome> read_outcome(ByteReader& reader) {
  Result<std::uint16_t> raw = reader.u16();
  if (!raw) {
    return raw.status();
  }
  if (raw.value() > static_cast<std::uint16_t>(Outcome::Internal)) {
    return invalid("outcome value is out of range");
  }
  return static_cast<Outcome>(raw.value());
}

Status check_end(ByteReader& reader) { return reader.expect_end(); }

Result<std::vector<std::byte>> finish(ByteWriter& writer) { return std::move(writer).take(); }

}  // namespace

const char* to_string(QueryKind kind) noexcept {
  switch (kind) {
    case QueryKind::Status:
      return "status";
    case QueryKind::ListClusters:
      return "clusters";
    case QueryKind::ShowCluster:
      return "cluster";
    case QueryKind::ListLinks:
      return "links";
    case QueryKind::ListPaths:
      return "paths";
    case QueryKind::ListPolicies:
      return "policies";
    case QueryKind::ListContracts:
      return "contracts";
    case QueryKind::ShowContract:
      return "contract";
    case QueryKind::ListGrants:
      return "grants";
    case QueryKind::ShowGrant:
      return "grant";
    case QueryKind::ListReservations:
      return "reservations";
    case QueryKind::ListAudit:
      return "audit";
    case QueryKind::Decide:
      return "decide";
    case QueryKind::FencePlan:
      return "fence-plan";
    case QueryKind::Accounting:
      return "accounting";
  }
  return "status";
}

const char* to_string(AdminAction action) noexcept {
  switch (action) {
    case AdminAction::UpsertCluster:
      return "upsert-cluster";
    case AdminAction::DeleteCluster:
      return "delete-cluster";
    case AdminAction::SetClusterState:
      return "set-cluster-state";
    case AdminAction::UpsertLink:
      return "upsert-link";
    case AdminAction::SetLinkState:
      return "set-link-state";
    case AdminAction::DeleteLink:
      return "delete-link";
    case AdminAction::UpsertPath:
      return "upsert-path";
    case AdminAction::DeletePath:
      return "delete-path";
    case AdminAction::UpsertPolicy:
      return "upsert-policy";
    case AdminAction::DeletePolicy:
      return "delete-policy";
    case AdminAction::WithdrawConsent:
      return "withdraw-consent";
    case AdminAction::RestoreConsent:
      return "restore-consent";
    case AdminAction::ResolveConflict:
      return "resolve-conflict";
    case AdminAction::AuthorizeContract:
      return "authorize-contract";
    case AdminAction::IssueGrant:
      return "issue-grant";
    case AdminAction::RevalidateGrant:
      return "revalidate-grant";
    case AdminAction::FenceGrant:
      return "fence-grant";
    case AdminAction::ReloadStore:
      return "reload-store";
  }
  return "upsert-cluster";
}

bool query_kind_from_string(std::string_view text, QueryKind& out) noexcept {
  for (std::uint8_t value = 1; value <= static_cast<std::uint8_t>(QueryKind::Accounting); ++value) {
    const auto candidate = static_cast<QueryKind>(value);
    if (text == to_string(candidate)) {
      out = candidate;
      return true;
    }
  }
  return false;
}

bool admin_action_from_string(std::string_view text, AdminAction& out) noexcept {
  for (std::uint8_t value = 1; value <= static_cast<std::uint8_t>(AdminAction::ReloadStore); ++value) {
    const auto candidate = static_cast<AdminAction>(value);
    if (text == to_string(candidate)) {
      out = candidate;
      return true;
    }
  }
  return false;
}

Result<std::vector<std::byte>> encode_message(const HelloMessage& message) {
  ByteWriter writer;
  writer.u8(static_cast<std::uint8_t>(message.role));
  write_name(writer, message.cluster);
  write_name(writer, message.domain);
  write_uuid(writer, message.incarnation.uuid());
  writer.u64(message.generation.value());
  writer.u64(message.policy_generation.value());
  writer.u64(message.agent_term.value());
  writer.u16(message.protocol_min);
  writer.u16(message.protocol_max);
  writer.u32(message.capabilities);
  writer.digest(message.content_digest);
  writer.i64(message.started_at.unix_nanos());
  return finish(writer);
}

Result<HelloMessage> decode_hello(ByteReader& reader) {
  HelloMessage message;
  Result<PeerRole> role = read_enum8<PeerRole>(reader, 2);
  if (!role) {
    return role.status();
  }
  message.role = role.value();
  Result<ClusterId> cluster = read_optional_name<ClusterId>(reader, limits::kMaxNameLength);
  if (!cluster) {
    return cluster.status();
  }
  message.cluster = cluster.value();
  Result<AuthorityDomainId> domain = read_optional_name<AuthorityDomainId>(reader, limits::kMaxNameLength);
  if (!domain) {
    return domain.status();
  }
  message.domain = domain.value();
  Result<Uuid> incarnation = read_uuid(reader);
  if (!incarnation) {
    return incarnation.status();
  }
  message.incarnation = IncarnationId::from_uuid(incarnation.value());
  Result<std::uint64_t> generation = read_counter(reader, limits::kMaxGeneration);
  if (!generation) {
    return generation.status();
  }
  message.generation = Generation(generation.value());
  Result<std::uint64_t> policy = read_counter(reader, limits::kMaxGeneration);
  if (!policy) {
    return policy.status();
  }
  message.policy_generation = PolicyGeneration(policy.value());
  Result<std::uint64_t> term = read_counter(reader, limits::kMaxGeneration);
  if (!term) {
    return term.status();
  }
  message.agent_term = Term(term.value());
  Result<std::uint16_t> protocol_min = reader.u16();
  if (!protocol_min) {
    return protocol_min.status();
  }
  Result<std::uint16_t> protocol_max = reader.u16();
  if (!protocol_max) {
    return protocol_max.status();
  }
  message.protocol_min = protocol_min.value();
  message.protocol_max = protocol_max.value();
  if (message.protocol_max < message.protocol_min) {
    return invalid("peer declared an inverted protocol version range");
  }
  Result<std::uint32_t> capabilities = reader.u32();
  if (!capabilities) {
    return capabilities.status();
  }
  message.capabilities = capabilities.value();
  Result<Digest> digest = reader.digest();
  if (!digest) {
    return digest.status();
  }
  message.content_digest = digest.value();
  Result<std::int64_t> started = reader.i64();
  if (!started) {
    return started.status();
  }
  message.started_at = Timestamp::from_unix_nanos(started.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const HelloAckMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  write_uuid(writer, message.coordinator.uuid());
  writer.u64(message.coordinator_term.value());
  writer.u16(static_cast<std::uint16_t>(message.outcome));
  writer.u16(message.negotiated_version);
  writer.digest(message.view_digest);
  (void)writer.count(message.revalidate.size());
  for (const GrantId& grant : message.revalidate) {
    write_uuid(writer, grant.uuid());
  }
  write_text(writer, message.detail);
  return finish(writer);
}

Result<HelloAckMessage> decode_hello_ack(ByteReader& reader) {
  HelloAckMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<Uuid> coordinator = read_uuid(reader);
  if (!coordinator) {
    return coordinator.status();
  }
  message.coordinator = IncarnationId::from_uuid(coordinator.value());
  Result<std::uint64_t> term = read_counter(reader, limits::kMaxGeneration);
  if (!term) {
    return term.status();
  }
  message.coordinator_term = Term(term.value());
  Result<Outcome> outcome = read_outcome(reader);
  if (!outcome) {
    return outcome.status();
  }
  message.outcome = outcome.value();
  Result<std::uint16_t> version = reader.u16();
  if (!version) {
    return version.status();
  }
  message.negotiated_version = version.value();
  Result<Digest> digest = reader.digest();
  if (!digest) {
    return digest.status();
  }
  message.view_digest = digest.value();
  Result<std::size_t> count = reader.count(limits::kMaxGrants);
  if (!count) {
    return count.status();
  }
  message.revalidate.reserve(count.value());
  for (std::size_t i = 0; i < count.value(); ++i) {
    Result<Uuid> grant = read_uuid(reader);
    if (!grant) {
      return grant.status();
    }
    message.revalidate.push_back(GrantId::from_uuid(grant.value()));
  }
  Result<std::string> detail = read_text(reader);
  if (!detail) {
    return detail.status();
  }
  message.detail = std::move(detail.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const RefuseMessage& message) {
  ByteWriter writer;
  writer.u16(static_cast<std::uint16_t>(message.outcome));
  write_text(writer, message.detail);
  return finish(writer);
}

Result<RefuseMessage> decode_refuse(ByteReader& reader) {
  RefuseMessage message;
  Result<Outcome> outcome = read_outcome(reader);
  if (!outcome) {
    return outcome.status();
  }
  message.outcome = outcome.value();
  Result<std::string> detail = read_text(reader);
  if (!detail) {
    return detail.status();
  }
  message.detail = std::move(detail.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const PingMessage& message) {
  ByteWriter writer;
  writer.u64(message.sequence.value());
  writer.i64(message.sent_at.unix_nanos());
  return finish(writer);
}

Result<PingMessage> decode_ping(ByteReader& reader) {
  PingMessage message;
  Result<std::uint64_t> sequence = read_counter(reader, limits::kMaxGeneration);
  if (!sequence) {
    return sequence.status();
  }
  message.sequence = Sequence(sequence.value());
  Result<std::int64_t> sent = reader.i64();
  if (!sent) {
    return sent.status();
  }
  message.sent_at = Timestamp::from_unix_nanos(sent.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const PongMessage& message) {
  ByteWriter writer;
  writer.u64(message.sequence.value());
  return finish(writer);
}

Result<PongMessage> decode_pong(ByteReader& reader) {
  PongMessage message;
  Result<std::uint64_t> sequence = read_counter(reader, limits::kMaxGeneration);
  if (!sequence) {
    return sequence.status();
  }
  message.sequence = Sequence(sequence.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const ReportClusterMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  model::encode_cluster(message.cluster, writer);
  return finish(writer);
}

Result<ReportClusterMessage> decode_report_cluster(ByteReader& reader) {
  ReportClusterMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<ClusterRecord> cluster = model::decode_cluster(reader);
  if (!cluster) {
    return cluster.status();
  }
  message.cluster = std::move(cluster.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const ReportAckMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  writer.u16(static_cast<std::uint16_t>(message.outcome));
  writer.u64(message.revision.value());
  writer.digest(message.view_digest);
  write_text(writer, message.detail);
  return finish(writer);
}

Result<ReportAckMessage> decode_report_ack(ByteReader& reader) {
  ReportAckMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<Outcome> outcome = read_outcome(reader);
  if (!outcome) {
    return outcome.status();
  }
  message.outcome = outcome.value();
  Result<std::uint64_t> revision = read_counter(reader, limits::kMaxGeneration);
  if (!revision) {
    return revision.status();
  }
  message.revision = Revision(revision.value());
  Result<Digest> digest = reader.digest();
  if (!digest) {
    return digest.status();
  }
  message.view_digest = digest.value();
  Result<std::string> detail = read_text(reader);
  if (!detail) {
    return detail.status();
  }
  message.detail = std::move(detail.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const ProposeContractMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  write_uuid(writer, message.contract.uuid());
  model::encode_terms(message.terms, writer);
  write_uuid(writer, message.attempt.uuid());
  return finish(writer);
}

Result<ProposeContractMessage> decode_propose_contract(ByteReader& reader) {
  ProposeContractMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<Uuid> contract = read_uuid(reader);
  if (!contract) {
    return contract.status();
  }
  message.contract = ContractId::from_uuid(contract.value());
  Result<model::ContractTerms> terms = model::decode_terms(reader);
  if (!terms) {
    return terms.status();
  }
  message.terms = std::move(terms.value());
  Result<Uuid> attempt = read_uuid(reader);
  if (!attempt) {
    return attempt.status();
  }
  message.attempt = AttemptId::from_uuid(attempt.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const ContractConsentMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  write_uuid(writer, message.contract.uuid());
  writer.digest(message.terms_digest);
  writer.u8(static_cast<std::uint8_t>(message.decision));
  write_name(writer, message.endpoint);
  write_uuid(writer, message.incarnation.uuid());
  writer.u64(message.generation.value());
  writer.u64(message.policy_generation.value());
  writer.u64(message.agent_term.value());
  write_text(writer, message.reason);
  return finish(writer);
}

Result<ContractConsentMessage> decode_contract_consent(ByteReader& reader) {
  ContractConsentMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<Uuid> contract = read_uuid(reader);
  if (!contract) {
    return contract.status();
  }
  message.contract = ContractId::from_uuid(contract.value());
  Result<Digest> terms = reader.digest();
  if (!terms) {
    return terms.status();
  }
  message.terms_digest = terms.value();
  Result<ConsentDecision> decision = read_enum8<ConsentDecision>(reader, 1);
  if (!decision) {
    return decision.status();
  }
  message.decision = decision.value();
  Result<EndpointId> endpoint = read_name<EndpointId>(reader, limits::kMaxNameLength);
  if (!endpoint) {
    return endpoint.status();
  }
  message.endpoint = endpoint.value();
  Result<Uuid> incarnation = read_uuid(reader);
  if (!incarnation) {
    return incarnation.status();
  }
  message.incarnation = IncarnationId::from_uuid(incarnation.value());
  Result<std::uint64_t> generation = read_counter(reader, limits::kMaxGeneration);
  if (!generation) {
    return generation.status();
  }
  message.generation = Generation(generation.value());
  Result<std::uint64_t> policy = read_counter(reader, limits::kMaxGeneration);
  if (!policy) {
    return policy.status();
  }
  message.policy_generation = PolicyGeneration(policy.value());
  Result<std::uint64_t> term = read_counter(reader, limits::kMaxGeneration);
  if (!term) {
    return term.status();
  }
  message.agent_term = Term(term.value());
  Result<std::string> reason = read_text(reader);
  if (!reason) {
    return reason.status();
  }
  message.reason = std::move(reason.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const PrepareGrantMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  model::encode_grant(message.grant, writer);
  return finish(writer);
}

Result<PrepareGrantMessage> decode_prepare_grant(ByteReader& reader) {
  PrepareGrantMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<GrantRecord> grant = model::decode_grant(reader);
  if (!grant) {
    return grant.status();
  }
  message.grant = std::move(grant.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const GrantPreparedMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  write_uuid(writer, message.grant.uuid());
  write_uuid(writer, message.attempt.uuid());
  writer.boolean(message.accepted);
  writer.u64(message.agent_term.value());
  writer.digest(message.enforcement_digest);
  write_text(writer, message.detail);
  return finish(writer);
}

Result<GrantPreparedMessage> decode_grant_prepared(ByteReader& reader) {
  GrantPreparedMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<Uuid> grant = read_uuid(reader);
  if (!grant) {
    return grant.status();
  }
  message.grant = GrantId::from_uuid(grant.value());
  Result<Uuid> attempt = read_uuid(reader);
  if (!attempt) {
    return attempt.status();
  }
  message.attempt = AttemptId::from_uuid(attempt.value());
  Result<bool> accepted = reader.boolean();
  if (!accepted) {
    return accepted.status();
  }
  message.accepted = accepted.value();
  Result<std::uint64_t> term = read_counter(reader, limits::kMaxGeneration);
  if (!term) {
    return term.status();
  }
  message.agent_term = Term(term.value());
  Result<Digest> digest = reader.digest();
  if (!digest) {
    return digest.status();
  }
  message.enforcement_digest = digest.value();
  Result<std::string> detail = read_text(reader);
  if (!detail) {
    return detail.status();
  }
  message.detail = std::move(detail.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const CommitGrantMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  write_uuid(writer, message.grant.uuid());
  write_uuid(writer, message.attempt.uuid());
  return finish(writer);
}

Result<CommitGrantMessage> decode_commit_grant(ByteReader& reader) {
  CommitGrantMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<Uuid> grant = read_uuid(reader);
  if (!grant) {
    return grant.status();
  }
  message.grant = GrantId::from_uuid(grant.value());
  Result<Uuid> attempt = read_uuid(reader);
  if (!attempt) {
    return attempt.status();
  }
  message.attempt = AttemptId::from_uuid(attempt.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const GrantCommittedMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  write_uuid(writer, message.grant.uuid());
  write_uuid(writer, message.attempt.uuid());
  writer.boolean(message.installed);
  writer.u64(message.agent_term.value());
  writer.digest(message.enforcement_digest);
  write_text(writer, message.detail);
  return finish(writer);
}

Result<GrantCommittedMessage> decode_grant_committed(ByteReader& reader) {
  GrantCommittedMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<Uuid> grant = read_uuid(reader);
  if (!grant) {
    return grant.status();
  }
  message.grant = GrantId::from_uuid(grant.value());
  Result<Uuid> attempt = read_uuid(reader);
  if (!attempt) {
    return attempt.status();
  }
  message.attempt = AttemptId::from_uuid(attempt.value());
  Result<bool> installed = reader.boolean();
  if (!installed) {
    return installed.status();
  }
  message.installed = installed.value();
  Result<std::uint64_t> term = read_counter(reader, limits::kMaxGeneration);
  if (!term) {
    return term.status();
  }
  message.agent_term = Term(term.value());
  Result<Digest> digest = reader.digest();
  if (!digest) {
    return digest.status();
  }
  message.enforcement_digest = digest.value();
  Result<std::string> detail = read_text(reader);
  if (!detail) {
    return detail.status();
  }
  message.detail = std::move(detail.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const AbortGrantMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  write_uuid(writer, message.grant.uuid());
  write_uuid(writer, message.attempt.uuid());
  write_text(writer, message.reason);
  return finish(writer);
}

Result<AbortGrantMessage> decode_abort_grant(ByteReader& reader) {
  AbortGrantMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<Uuid> grant = read_uuid(reader);
  if (!grant) {
    return grant.status();
  }
  message.grant = GrantId::from_uuid(grant.value());
  Result<Uuid> attempt = read_uuid(reader);
  if (!attempt) {
    return attempt.status();
  }
  message.attempt = AttemptId::from_uuid(attempt.value());
  Result<std::string> reason = read_text(reader);
  if (!reason) {
    return reason.status();
  }
  message.reason = std::move(reason.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const GrantAbortedMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  write_uuid(writer, message.grant.uuid());
  write_uuid(writer, message.attempt.uuid());
  write_text(writer, message.reason);
  return finish(writer);
}

Result<GrantAbortedMessage> decode_grant_aborted(ByteReader& reader) {
  GrantAbortedMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<Uuid> grant = read_uuid(reader);
  if (!grant) {
    return grant.status();
  }
  message.grant = GrantId::from_uuid(grant.value());
  Result<Uuid> attempt = read_uuid(reader);
  if (!attempt) {
    return attempt.status();
  }
  message.attempt = AttemptId::from_uuid(attempt.value());
  Result<std::string> reason = read_text(reader);
  if (!reason) {
    return reason.status();
  }
  message.reason = std::move(reason.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const FenceMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  writer.u64(message.coordinator_term.value());
  (void)writer.count(message.grants.size());
  for (const GrantId& grant : message.grants) {
    write_uuid(writer, grant.uuid());
  }
  write_text(writer, message.reason);
  return finish(writer);
}

Result<FenceMessage> decode_fence(ByteReader& reader) {
  FenceMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<std::uint64_t> term = read_counter(reader, limits::kMaxGeneration);
  if (!term) {
    return term.status();
  }
  message.coordinator_term = Term(term.value());
  Result<std::size_t> count = reader.count(limits::kMaxGrants);
  if (!count) {
    return count.status();
  }
  message.grants.reserve(count.value());
  for (std::size_t i = 0; i < count.value(); ++i) {
    Result<Uuid> grant = read_uuid(reader);
    if (!grant) {
      return grant.status();
    }
    message.grants.push_back(GrantId::from_uuid(grant.value()));
  }
  Result<std::string> reason = read_text(reader);
  if (!reason) {
    return reason.status();
  }
  message.reason = std::move(reason.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const FenceAckMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  (void)writer.count(message.results.size());
  for (const FenceResult& result : message.results) {
    write_uuid(writer, result.grant.uuid());
    writer.u16(static_cast<std::uint16_t>(result.outcome));
  }
  return finish(writer);
}

Result<FenceAckMessage> decode_fence_ack(ByteReader& reader) {
  FenceAckMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<std::size_t> count = reader.count(limits::kMaxGrants);
  if (!count) {
    return count.status();
  }
  message.results.reserve(count.value());
  for (std::size_t i = 0; i < count.value(); ++i) {
    Result<Uuid> grant = read_uuid(reader);
    if (!grant) {
      return grant.status();
    }
    Result<Outcome> outcome = read_outcome(reader);
    if (!outcome) {
      return outcome.status();
    }
    FenceResult result;
    result.grant = GrantId::from_uuid(grant.value());
    result.outcome = outcome.value();
    message.results.push_back(result);
  }
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const WithdrawMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  write_name(writer, message.cluster);
  write_uuid(writer, message.incarnation.uuid());
  writer.u64(message.generation.value());
  write_text(writer, message.reason);
  return finish(writer);
}

Result<WithdrawMessage> decode_withdraw(ByteReader& reader) {
  WithdrawMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<ClusterId> cluster = read_name<ClusterId>(reader, limits::kMaxNameLength);
  if (!cluster) {
    return cluster.status();
  }
  message.cluster = cluster.value();
  Result<Uuid> incarnation = read_uuid(reader);
  if (!incarnation) {
    return incarnation.status();
  }
  message.incarnation = IncarnationId::from_uuid(incarnation.value());
  Result<std::uint64_t> generation = read_counter(reader, limits::kMaxGeneration);
  if (!generation) {
    return generation.status();
  }
  message.generation = Generation(generation.value());
  Result<std::string> reason = read_text(reader);
  if (!reason) {
    return reason.status();
  }
  message.reason = std::move(reason.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const WithdrawAckMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  writer.u16(static_cast<std::uint16_t>(message.outcome));
  writer.u64(message.fenced_grants);
  write_text(writer, message.detail);
  return finish(writer);
}

Result<WithdrawAckMessage> decode_withdraw_ack(ByteReader& reader) {
  WithdrawAckMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<Outcome> outcome = read_outcome(reader);
  if (!outcome) {
    return outcome.status();
  }
  message.outcome = outcome.value();
  Result<std::uint64_t> fenced = reader.u64();
  if (!fenced) {
    return fenced.status();
  }
  message.fenced_grants = fenced.value();
  Result<std::string> detail = read_text(reader);
  if (!detail) {
    return detail.status();
  }
  message.detail = std::move(detail.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const StatusRequestMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  write_uuid(writer, message.request);
  return finish(writer);
}

Result<StatusRequestMessage> decode_status_request(ByteReader& reader) {
  StatusRequestMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<Uuid> request = read_uuid(reader);
  if (!request) {
    return request.status();
  }
  message.request = request.value();
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const StatusReportMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.session.uuid());
  write_uuid(writer, message.request);
  write_name(writer, message.cluster);
  write_uuid(writer, message.incarnation.uuid());
  writer.u64(message.generation.value());
  writer.u64(message.policy_generation.value());
  writer.u64(message.agent_term.value());
  (void)writer.count(message.grants.size());
  for (const GrantStatusEntry& entry : message.grants) {
    write_uuid(writer, entry.grant.uuid());
    write_uuid(writer, entry.attempt.uuid());
    writer.u8(static_cast<std::uint8_t>(entry.state));
    writer.u64(entry.agent_term.value());
    writer.digest(entry.enforcement_digest);
  }
  return finish(writer);
}

Result<StatusReportMessage> decode_status_report(ByteReader& reader) {
  StatusReportMessage message;
  Result<Uuid> session = read_uuid(reader);
  if (!session) {
    return session.status();
  }
  message.session = SessionToken::from_uuid(session.value());
  Result<Uuid> request = read_uuid(reader);
  if (!request) {
    return request.status();
  }
  message.request = request.value();
  Result<ClusterId> cluster = read_name<ClusterId>(reader, limits::kMaxNameLength);
  if (!cluster) {
    return cluster.status();
  }
  message.cluster = cluster.value();
  Result<Uuid> incarnation = read_uuid(reader);
  if (!incarnation) {
    return incarnation.status();
  }
  message.incarnation = IncarnationId::from_uuid(incarnation.value());
  Result<std::uint64_t> generation = read_counter(reader, limits::kMaxGeneration);
  if (!generation) {
    return generation.status();
  }
  message.generation = Generation(generation.value());
  Result<std::uint64_t> policy = read_counter(reader, limits::kMaxGeneration);
  if (!policy) {
    return policy.status();
  }
  message.policy_generation = PolicyGeneration(policy.value());
  Result<std::uint64_t> term = read_counter(reader, limits::kMaxGeneration);
  if (!term) {
    return term.status();
  }
  message.agent_term = Term(term.value());
  Result<std::size_t> count = reader.count(limits::kMaxGrants);
  if (!count) {
    return count.status();
  }
  message.grants.reserve(count.value());
  for (std::size_t i = 0; i < count.value(); ++i) {
    GrantStatusEntry entry;
    Result<Uuid> grant = read_uuid(reader);
    if (!grant) {
      return grant.status();
    }
    Result<Uuid> attempt = read_uuid(reader);
    if (!attempt) {
      return attempt.status();
    }
    Result<GrantState> state = read_enum8<GrantState>(reader, 8);
    if (!state) {
      return state.status();
    }
    Result<std::uint64_t> entry_term = read_counter(reader, limits::kMaxGeneration);
    if (!entry_term) {
      return entry_term.status();
    }
    Result<Digest> digest = reader.digest();
    if (!digest) {
      return digest.status();
    }
    entry.grant = GrantId::from_uuid(grant.value());
    entry.attempt = AttemptId::from_uuid(attempt.value());
    entry.state = state.value();
    entry.agent_term = Term(entry_term.value());
    entry.enforcement_digest = digest.value();
    message.grants.push_back(entry);
  }
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const QueryMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.request);
  writer.u8(static_cast<std::uint8_t>(message.kind));
  write_name(writer, message.cluster);
  write_name(writer, message.cluster_b);
  write_name(writer, message.endpoint);
  write_name(writer, message.endpoint_b);
  write_uuid(writer, message.contract.uuid());
  write_uuid(writer, message.grant.uuid());
  write_name(writer, message.edge);
  write_text(writer, message.policy_id);
  writer.u64(message.capacity.value());
  writer.boolean(message.allow_degraded);
  writer.u32(message.limit);
  writer.boolean(message.expect_source_generation);
  writer.u64(message.source_generation.value());
  writer.boolean(message.expect_target_generation);
  writer.u64(message.target_generation.value());
  writer.i64(message.at.unix_nanos());
  return finish(writer);
}

Result<QueryMessage> decode_query(ByteReader& reader) {
  QueryMessage message;
  Result<Uuid> request = read_uuid(reader);
  if (!request) {
    return request.status();
  }
  message.request = request.value();
  Result<QueryKind> kind = read_enum8<QueryKind>(reader, static_cast<std::uint8_t>(QueryKind::Accounting));
  if (!kind) {
    return kind.status();
  }
  message.kind = kind.value();
  auto read_optional_name = [&reader](auto& target, std::size_t max_length) -> Status {
    using Target = std::decay_t<decltype(target)>;
    Result<std::string> text = reader.blob(max_length);
    if (!text) {
      return text.status();
    }
    if (text.value().empty()) {
      target = Target{};
      return Status::ok();
    }
    Result<Target> parsed = Target::parse(text.value());
    if (!parsed) {
      return parsed.status();
    }
    target = parsed.value();
    return Status::ok();
  };
  Status status = read_optional_name(message.cluster, limits::kMaxNameLength);
  if (!status) {
    return status;
  }
  status = read_optional_name(message.cluster_b, limits::kMaxNameLength);
  if (!status) {
    return status;
  }
  status = read_optional_name(message.endpoint, limits::kMaxNameLength);
  if (!status) {
    return status;
  }
  status = read_optional_name(message.endpoint_b, limits::kMaxNameLength);
  if (!status) {
    return status;
  }
  Result<Uuid> contract = read_uuid(reader);
  if (!contract) {
    return contract.status();
  }
  message.contract = ContractId::from_uuid(contract.value());
  Result<Uuid> grant = read_uuid(reader);
  if (!grant) {
    return grant.status();
  }
  message.grant = GrantId::from_uuid(grant.value());
  status = read_optional_name(message.edge, limits::kMaxNameLength);
  if (!status) {
    return status;
  }
  Result<std::string> policy = read_text(reader);
  if (!policy) {
    return policy.status();
  }
  message.policy_id = std::move(policy.value());
  Result<std::uint64_t> capacity = read_counter(reader, limits::kMaxCapacity);
  if (!capacity) {
    return capacity.status();
  }
  message.capacity = CapacityUnits(capacity.value());
  Result<bool> allow_degraded = reader.boolean();
  if (!allow_degraded) {
    return allow_degraded.status();
  }
  message.allow_degraded = allow_degraded.value();
  Result<std::uint32_t> limit = reader.u32();
  if (!limit) {
    return limit.status();
  }
  if (limit.value() > limits::kMaxQueryResults) {
    return invalid("query result limit exceeds the maximum");
  }
  message.limit = limit.value();
  Result<bool> expect_source = reader.boolean();
  if (!expect_source) {
    return expect_source.status();
  }
  message.expect_source_generation = expect_source.value();
  Result<std::uint64_t> source_generation = read_counter(reader, limits::kMaxGeneration);
  if (!source_generation) {
    return source_generation.status();
  }
  message.source_generation = Generation(source_generation.value());
  Result<bool> expect_target = reader.boolean();
  if (!expect_target) {
    return expect_target.status();
  }
  message.expect_target_generation = expect_target.value();
  Result<std::uint64_t> target_generation = read_counter(reader, limits::kMaxGeneration);
  if (!target_generation) {
    return target_generation.status();
  }
  message.target_generation = Generation(target_generation.value());
  Result<std::int64_t> at = reader.i64();
  if (!at) {
    return at.status();
  }
  message.at = Timestamp::from_unix_nanos(at.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const QueryResultMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.request);
  writer.u8(static_cast<std::uint8_t>(message.kind));
  writer.u16(static_cast<std::uint16_t>(message.outcome));
  write_text(writer, message.detail);

  auto encode_clusters = [&writer](const std::vector<ClusterRecord>& records) {
    (void)writer.count(records.size());
    for (const ClusterRecord& record : records) {
      model::encode_cluster(record, writer);
    }
  };
  auto encode_links = [&writer](const std::vector<LinkRecord>& records) {
    (void)writer.count(records.size());
    for (const LinkRecord& record : records) {
      model::encode_link(record, writer);
    }
  };
  auto encode_paths = [&writer](const std::vector<PathRecord>& records) {
    (void)writer.count(records.size());
    for (const PathRecord& record : records) {
      model::encode_path(record, writer);
    }
  };
  auto encode_policies = [&writer](const std::vector<PolicyRule>& records) {
    (void)writer.count(records.size());
    for (const PolicyRule& record : records) {
      model::encode_policy(record, writer);
    }
  };
  auto encode_contracts = [&writer](const std::vector<ContractRecord>& records) {
    (void)writer.count(records.size());
    for (const ContractRecord& record : records) {
      model::encode_contract(record, writer);
    }
  };
  auto encode_grants = [&writer](const std::vector<GrantRecord>& records) {
    (void)writer.count(records.size());
    for (const GrantRecord& record : records) {
      model::encode_grant(record, writer);
    }
  };
  auto encode_reservations = [&writer](const std::vector<ReservationRecord>& records) {
    (void)writer.count(records.size());
    for (const ReservationRecord& record : records) {
      model::encode_reservation(record, writer);
    }
  };
  auto encode_audit = [&writer](const std::vector<AuditRecord>& records) {
    (void)writer.count(records.size());
    for (const AuditRecord& record : records) {
      model::encode_audit(record, writer);
    }
  };

  switch (message.kind) {
    case QueryKind::Status:
      writer.boolean(message.status.has_value());
      if (message.status.has_value()) {
        model::encode_status(*message.status, writer);
      }
      break;
    case QueryKind::ListClusters:
    case QueryKind::ShowCluster:
      encode_clusters(message.clusters);
      break;
    case QueryKind::ListLinks:
      encode_links(message.links);
      break;
    case QueryKind::ListPaths:
      encode_paths(message.paths);
      break;
    case QueryKind::ListPolicies:
      encode_policies(message.policies);
      break;
    case QueryKind::ListContracts:
    case QueryKind::ShowContract:
      encode_contracts(message.contracts);
      break;
    case QueryKind::ListGrants:
    case QueryKind::ShowGrant:
      encode_grants(message.grants);
      break;
    case QueryKind::ListReservations:
      encode_reservations(message.reservations);
      break;
    case QueryKind::ListAudit:
      encode_audit(message.audit);
      break;
    case QueryKind::Decide:
      writer.boolean(message.decision.has_value());
      if (message.decision.has_value()) {
        model::encode_decision(*message.decision, writer);
      }
      break;
    case QueryKind::FencePlan:
      writer.boolean(message.fence_plan.has_value());
      if (message.fence_plan.has_value()) {
        model::encode_fence_plan(*message.fence_plan, writer);
      }
      break;
    case QueryKind::Accounting:
      (void)writer.count(message.accounting.size());
      for (const AccountingEntry& entry : message.accounting) {
        model::encode_accounting(entry, writer);
      }
      break;
  }
  return finish(writer);
}

Result<QueryResultMessage> decode_query_result(ByteReader& reader) {
  QueryResultMessage message;
  Result<Uuid> request = read_uuid(reader);
  if (!request) {
    return request.status();
  }
  message.request = request.value();
  Result<QueryKind> kind = read_enum8<QueryKind>(reader, static_cast<std::uint8_t>(QueryKind::Accounting));
  if (!kind) {
    return kind.status();
  }
  message.kind = kind.value();
  Result<Outcome> outcome = read_outcome(reader);
  if (!outcome) {
    return outcome.status();
  }
  message.outcome = outcome.value();
  Result<std::string> detail = read_text(reader);
  if (!detail) {
    return detail.status();
  }
  message.detail = std::move(detail.value());

  switch (message.kind) {
    case QueryKind::Status: {
      Result<bool> present = reader.boolean();
      if (!present) {
        return present.status();
      }
      if (present.value()) {
        Result<CoordinatorStatus> status = model::decode_status(reader);
        if (!status) {
          return status.status();
        }
        message.status = status.value();
      }
      break;
    }
    case QueryKind::ListClusters:
    case QueryKind::ShowCluster: {
      Result<std::size_t> count = reader.count(limits::kMaxClusters);
      if (!count) {
        return count.status();
      }
      for (std::size_t i = 0; i < count.value(); ++i) {
        Result<ClusterRecord> record = model::decode_cluster(reader);
        if (!record) {
          return record.status();
        }
        message.clusters.push_back(std::move(record.value()));
      }
      break;
    }
    case QueryKind::ListLinks: {
      Result<std::size_t> count = reader.count(limits::kMaxEdges);
      if (!count) {
        return count.status();
      }
      for (std::size_t i = 0; i < count.value(); ++i) {
        Result<LinkRecord> record = model::decode_link(reader);
        if (!record) {
          return record.status();
        }
        message.links.push_back(std::move(record.value()));
      }
      break;
    }
    case QueryKind::ListPaths: {
      Result<std::size_t> count = reader.count(limits::kMaxPaths);
      if (!count) {
        return count.status();
      }
      for (std::size_t i = 0; i < count.value(); ++i) {
        Result<PathRecord> record = model::decode_path(reader);
        if (!record) {
          return record.status();
        }
        message.paths.push_back(std::move(record.value()));
      }
      break;
    }
    case QueryKind::ListPolicies: {
      Result<std::size_t> count = reader.count(limits::kMaxPolicyRules);
      if (!count) {
        return count.status();
      }
      for (std::size_t i = 0; i < count.value(); ++i) {
        Result<PolicyRule> record = model::decode_policy(reader);
        if (!record) {
          return record.status();
        }
        message.policies.push_back(std::move(record.value()));
      }
      break;
    }
    case QueryKind::ListContracts:
    case QueryKind::ShowContract: {
      Result<std::size_t> count = reader.count(limits::kMaxContracts);
      if (!count) {
        return count.status();
      }
      for (std::size_t i = 0; i < count.value(); ++i) {
        Result<ContractRecord> record = model::decode_contract(reader);
        if (!record) {
          return record.status();
        }
        message.contracts.push_back(std::move(record.value()));
      }
      break;
    }
    case QueryKind::ListGrants:
    case QueryKind::ShowGrant: {
      Result<std::size_t> count = reader.count(limits::kMaxGrants);
      if (!count) {
        return count.status();
      }
      for (std::size_t i = 0; i < count.value(); ++i) {
        Result<GrantRecord> record = model::decode_grant(reader);
        if (!record) {
          return record.status();
        }
        message.grants.push_back(std::move(record.value()));
      }
      break;
    }
    case QueryKind::ListReservations: {
      Result<std::size_t> count = reader.count(limits::kMaxReservations);
      if (!count) {
        return count.status();
      }
      for (std::size_t i = 0; i < count.value(); ++i) {
        Result<ReservationRecord> record = model::decode_reservation(reader);
        if (!record) {
          return record.status();
        }
        message.reservations.push_back(std::move(record.value()));
      }
      break;
    }
    case QueryKind::ListAudit: {
      Result<std::size_t> count = reader.count(limits::kMaxAuditRecords);
      if (!count) {
        return count.status();
      }
      for (std::size_t i = 0; i < count.value(); ++i) {
        Result<AuditRecord> record = model::decode_audit(reader);
        if (!record) {
          return record.status();
        }
        message.audit.push_back(std::move(record.value()));
      }
      break;
    }
    case QueryKind::Decide: {
      Result<bool> present = reader.boolean();
      if (!present) {
        return present.status();
      }
      if (present.value()) {
        Result<Decision> decision = model::decode_decision(reader);
        if (!decision) {
          return decision.status();
        }
        message.decision = decision.value();
      }
      break;
    }
    case QueryKind::FencePlan: {
      Result<bool> present = reader.boolean();
      if (!present) {
        return present.status();
      }
      if (present.value()) {
        Result<FencePlan> plan = model::decode_fence_plan(reader);
        if (!plan) {
          return plan.status();
        }
        message.fence_plan = plan.value();
      }
      break;
    }
    case QueryKind::Accounting: {
      Result<std::size_t> count = reader.count(limits::kMaxReservations);
      if (!count) {
        return count.status();
      }
      for (std::size_t i = 0; i < count.value(); ++i) {
        Result<AccountingEntry> entry = model::decode_accounting(reader);
        if (!entry) {
          return entry.status();
        }
        message.accounting.push_back(std::move(entry.value()));
      }
      break;
    }
  }
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const AdminMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.request);
  writer.u8(static_cast<std::uint8_t>(message.action));
  writer.boolean(message.cluster.has_value());
  if (message.cluster.has_value()) {
    model::encode_cluster(*message.cluster, writer);
  }
  writer.boolean(message.link.has_value());
  if (message.link.has_value()) {
    model::encode_link(*message.link, writer);
  }
  writer.boolean(message.path.has_value());
  if (message.path.has_value()) {
    model::encode_path(*message.path, writer);
  }
  writer.boolean(message.policy.has_value());
  if (message.policy.has_value()) {
    model::encode_policy(*message.policy, writer);
  }
  write_name(writer, message.cluster_id);
  write_name(writer, message.cluster_b);
  write_name(writer, message.endpoint);
  write_name(writer, message.endpoint_b);
  write_uuid(writer, message.contract.uuid());
  write_uuid(writer, message.grant.uuid());
  write_name(writer, message.edge);
  write_text(writer, message.policy_id);
  writer.u64(message.generation.value());
  writer.u8(static_cast<std::uint8_t>(message.cluster_state));
  writer.u8(static_cast<std::uint8_t>(message.link_state));
  writer.u64(message.capacity.value());
  writer.i64(message.lease_duration.nanos());
  write_text(writer, message.reason);
  return finish(writer);
}

Result<AdminMessage> decode_admin(ByteReader& reader) {
  AdminMessage message;
  Result<Uuid> request = read_uuid(reader);
  if (!request) {
    return request.status();
  }
  message.request = request.value();
  Result<AdminAction> action = read_enum8<AdminAction>(reader, static_cast<std::uint8_t>(AdminAction::ReloadStore));
  if (!action) {
    return action.status();
  }
  message.action = action.value();
  Result<bool> has_cluster = reader.boolean();
  if (!has_cluster) {
    return has_cluster.status();
  }
  if (has_cluster.value()) {
    Result<ClusterRecord> record = model::decode_cluster(reader);
    if (!record) {
      return record.status();
    }
    message.cluster = std::move(record.value());
  }
  Result<bool> has_link = reader.boolean();
  if (!has_link) {
    return has_link.status();
  }
  if (has_link.value()) {
    Result<LinkRecord> record = model::decode_link(reader);
    if (!record) {
      return record.status();
    }
    message.link = std::move(record.value());
  }
  Result<bool> has_path = reader.boolean();
  if (!has_path) {
    return has_path.status();
  }
  if (has_path.value()) {
    Result<PathRecord> record = model::decode_path(reader);
    if (!record) {
      return record.status();
    }
    message.path = std::move(record.value());
  }
  Result<bool> has_policy = reader.boolean();
  if (!has_policy) {
    return has_policy.status();
  }
  if (has_policy.value()) {
    Result<PolicyRule> record = model::decode_policy(reader);
    if (!record) {
      return record.status();
    }
    message.policy = std::move(record.value());
  }
  auto read_optional_name = [&reader](auto& target, std::size_t max_length) -> Status {
    using Target = std::decay_t<decltype(target)>;
    Result<std::string> text = reader.blob(max_length);
    if (!text) {
      return text.status();
    }
    if (text.value().empty()) {
      target = Target{};
      return Status::ok();
    }
    Result<Target> parsed = Target::parse(text.value());
    if (!parsed) {
      return parsed.status();
    }
    target = parsed.value();
    return Status::ok();
  };
  Status status = read_optional_name(message.cluster_id, limits::kMaxNameLength);
  if (!status) {
    return status;
  }
  status = read_optional_name(message.cluster_b, limits::kMaxNameLength);
  if (!status) {
    return status;
  }
  status = read_optional_name(message.endpoint, limits::kMaxNameLength);
  if (!status) {
    return status;
  }
  status = read_optional_name(message.endpoint_b, limits::kMaxNameLength);
  if (!status) {
    return status;
  }
  Result<Uuid> contract = read_uuid(reader);
  if (!contract) {
    return contract.status();
  }
  message.contract = ContractId::from_uuid(contract.value());
  Result<Uuid> grant = read_uuid(reader);
  if (!grant) {
    return grant.status();
  }
  message.grant = GrantId::from_uuid(grant.value());
  status = read_optional_name(message.edge, limits::kMaxNameLength);
  if (!status) {
    return status;
  }
  Result<std::string> policy_id = read_text(reader);
  if (!policy_id) {
    return policy_id.status();
  }
  message.policy_id = std::move(policy_id.value());
  Result<std::uint64_t> generation = read_counter(reader, limits::kMaxGeneration);
  if (!generation) {
    return generation.status();
  }
  message.generation = Generation(generation.value());
  Result<ClusterState> cluster_state = read_enum8<ClusterState>(reader, 4);
  if (!cluster_state) {
    return cluster_state.status();
  }
  message.cluster_state = cluster_state.value();
  Result<LinkState> link_state = read_enum8<LinkState>(reader, 4);
  if (!link_state) {
    return link_state.status();
  }
  message.link_state = link_state.value();
  Result<std::uint64_t> capacity = read_counter(reader, limits::kMaxCapacity);
  if (!capacity) {
    return capacity.status();
  }
  message.capacity = CapacityUnits(capacity.value());
  Result<std::int64_t> lease = reader.i64();
  if (!lease) {
    return lease.status();
  }
  if (lease.value() < 0 || static_cast<std::uint64_t>(lease.value()) > limits::kMaxDurationNanos) {
    return invalid("lease duration is out of range");
  }
  message.lease_duration = Duration::from_nanos(lease.value());
  Result<std::string> reason = read_text(reader);
  if (!reason) {
    return reason.status();
  }
  message.reason = std::move(reason.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const AdminResultMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.request);
  writer.u16(static_cast<std::uint16_t>(message.outcome));
  write_text(writer, message.detail);
  writer.digest(message.view_digest);
  writer.u64(message.revision.value());
  write_uuid(writer, message.contract.uuid());
  write_uuid(writer, message.grant.uuid());
  return finish(writer);
}

Result<AdminResultMessage> decode_admin_result(ByteReader& reader) {
  AdminResultMessage message;
  Result<Uuid> request = read_uuid(reader);
  if (!request) {
    return request.status();
  }
  message.request = request.value();
  Result<Outcome> outcome = read_outcome(reader);
  if (!outcome) {
    return outcome.status();
  }
  message.outcome = outcome.value();
  Result<std::string> detail = read_text(reader);
  if (!detail) {
    return detail.status();
  }
  message.detail = std::move(detail.value());
  Result<Digest> digest = reader.digest();
  if (!digest) {
    return digest.status();
  }
  message.view_digest = digest.value();
  Result<std::uint64_t> revision = read_counter(reader, limits::kMaxGeneration);
  if (!revision) {
    return revision.status();
  }
  message.revision = Revision(revision.value());
  Result<Uuid> contract = read_uuid(reader);
  if (!contract) {
    return contract.status();
  }
  message.contract = ContractId::from_uuid(contract.value());
  Result<Uuid> grant = read_uuid(reader);
  if (!grant) {
    return grant.status();
  }
  message.grant = GrantId::from_uuid(grant.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

Result<std::vector<std::byte>> encode_message(const ErrorMessage& message) {
  ByteWriter writer;
  write_uuid(writer, message.request);
  writer.u16(static_cast<std::uint16_t>(message.outcome));
  write_text(writer, message.detail);
  return finish(writer);
}

Result<ErrorMessage> decode_error(ByteReader& reader) {
  ErrorMessage message;
  Result<Uuid> request = read_uuid(reader);
  if (!request) {
    return request.status();
  }
  message.request = request.value();
  Result<Outcome> outcome = read_outcome(reader);
  if (!outcome) {
    return outcome.status();
  }
  message.outcome = outcome.value();
  Result<std::string> detail = read_text(reader);
  if (!detail) {
    return detail.status();
  }
  message.detail = std::move(detail.value());
  const Status end = check_end(reader);
  if (!end) {
    return end;
  }
  return message;
}

}  // namespace icf::wire
