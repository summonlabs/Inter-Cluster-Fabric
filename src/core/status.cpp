#include "icf/core/status.hpp"

#include <algorithm>
#include <array>
#include <utility>

#include "icf/core/limits.hpp"

namespace icf {
namespace {

struct OutcomeName {
  Outcome outcome;
  const char* name;
};

constexpr std::array<OutcomeName, 26> kOutcomeNames{{
    {Outcome::Ok, "OK"},
    {Outcome::Unknown, "UNKNOWN"},
    {Outcome::Unsupported, "UNSUPPORTED"},
    {Outcome::Stale, "STALE"},
    {Outcome::Conflicting, "CONFLICTING"},
    {Outcome::Incomplete, "INCOMPLETE"},
    {Outcome::Indeterminate, "INDETERMINATE"},
    {Outcome::Refused, "REFUSED"},
    {Outcome::Cancelled, "CANCELLED"},
    {Outcome::Invalid, "INVALID"},
    {Outcome::Unreachable, "UNREACHABLE"},
    {Outcome::Partitioned, "PARTITIONED"},
    {Outcome::DegradedAuthorized, "DEGRADED_AUTHORIZED"},
    {Outcome::Fenced, "FENCED"},
    {Outcome::Expired, "EXPIRED"},
    {Outcome::Unauthorized, "UNAUTHORIZED"},
    {Outcome::NotFound, "NOT_FOUND"},
    {Outcome::CapacityExceeded, "CAPACITY_EXCEEDED"},
    {Outcome::Replayed, "REPLAYED"},
    {Outcome::Reincarnated, "REINCARNATED"},
    {Outcome::Corrupt, "CORRUPT"},
    {Outcome::Incompatible, "INCOMPATIBLE"},
    {Outcome::Overflow, "OVERFLOW"},
    {Outcome::Busy, "BUSY"},
    {Outcome::AlreadyExists, "ALREADY_EXISTS"},
    {Outcome::Internal, "INTERNAL"},
}};

}  // namespace

const char* to_string(Outcome outcome) noexcept {
  for (const OutcomeName& entry : kOutcomeNames) {
    if (entry.outcome == outcome) {
      return entry.name;
    }
  }
  return "INVALID";
}

bool is_ok(Outcome outcome) noexcept { return outcome == Outcome::Ok; }

bool is_authorized(Outcome outcome) noexcept {
  return outcome == Outcome::Ok || outcome == Outcome::DegradedAuthorized;
}

bool is_indeterminate_family(Outcome outcome) noexcept {
  switch (outcome) {
    case Outcome::Unknown:
    case Outcome::Incomplete:
    case Outcome::Indeterminate:
    case Outcome::Unreachable:
    case Outcome::Partitioned:
    case Outcome::Stale:
    case Outcome::Busy:
    case Outcome::Cancelled:
      return true;
    default:
      return false;
  }
}

bool outcome_from_string(std::string_view text, Outcome& out) noexcept {
  for (const OutcomeName& entry : kOutcomeNames) {
    if (text == entry.name) {
      out = entry.outcome;
      return true;
    }
  }
  return false;
}

Status Status::make(Outcome outcome, std::string message) {
  Status status;
  status.outcome_ = outcome;
  if (message.size() > limits::kMaxStringField) {
    message.resize(limits::kMaxStringField);
  }
  status.message_ = std::move(message);
  return status;
}

std::string Status::to_string() const {
  std::string result = icf::to_string(outcome_);
  if (!message_.empty()) {
    result += ": ";
    result += message_;
  }
  return result;
}

}  // namespace icf
