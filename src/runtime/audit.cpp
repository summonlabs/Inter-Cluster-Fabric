#include "icf/runtime/audit.hpp"

#include "icf/core/limits.hpp"

namespace icf::runtime {
namespace {

std::string bounded(std::string value, std::size_t limit) {
  if (value.size() > limit) {
    value.resize(limit);
  }
  return value;
}

}  // namespace

Status append_audit(model::Registry& registry, Timestamp at, std::string actor, std::string action,
                    std::string subject, Outcome outcome, std::string detail) {
  model::AuditRecord record;
  const std::vector<model::AuditRecord>& trail = registry.audit();
  record.sequence = trail.empty() ? Sequence(1) : trail.back().sequence.next().value();
  record.at = at;
  record.actor = bounded(std::move(actor), 64);
  record.action = bounded(std::move(action), 64);
  record.subject = bounded(std::move(subject), 128);
  record.outcome = outcome;
  record.detail = bounded(std::move(detail), limits::kMaxStringField);
  return registry.append_audit(std::move(record));
}

}  // namespace icf::runtime
