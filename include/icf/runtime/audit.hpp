// Inter-Cluster Fabric - audit trail helper.
//
// Every state change that can affect authorization is recorded with a contiguous sequence, the
// acting identity, the subject, and the typed outcome. The audit trail is bounded by
// limits::kMaxAuditRecords and never transmitted anywhere.
#pragma once

#include <string>
#include <string_view>

#include "icf/model/registry.hpp"

namespace icf::runtime {

[[nodiscard]] Status append_audit(model::Registry& registry, Timestamp at, std::string actor, std::string action,
                                  std::string subject, Outcome outcome, std::string detail);

}  // namespace icf::runtime
