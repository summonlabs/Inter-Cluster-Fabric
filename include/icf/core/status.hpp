// Inter-Cluster Fabric - typed outcomes.
//
// The runtime never collapses distinct negative results into a single failure: a missing
// observation is UNKNOWN, a refused peering is REFUSED, an observation tied to a superseded
// incarnation is STALE, and an unresolved two-sided commit is INDETERMINATE. Only Outcome::Ok
// means success. Outcome::DegradedAuthorized is the single authorized-but-degraded result and
// is never reported as Ok.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace icf {

enum class Outcome : std::uint16_t {
  Ok = 0,
  Unknown,             // the runtime holds no evidence either way
  Unsupported,         // the requested behavior is not supported by this build/link/peer
  Stale,               // evidence exists but is bound to a superseded generation/incarnation
  Conflicting,         // two authoritative updates disagree at the same generation
  Incomplete,          // required evidence has not been supplied yet
  Indeterminate,       // the runtime cannot decide (unresolved commit/ack ambiguity)
  Refused,             // administratively refused by an authority domain
  Cancelled,           // the requester abandoned the operation
  Invalid,             // malformed input rejected before use
  Unreachable,         // transport-level failure to reach a peer
  Partitioned,         // no live path exists between the two endpoint scopes
  DegradedAuthorized,  // authorized, but only over a degraded path
  Fenced,              // an older epoch/incarnation/generation was superseded
  Expired,             // the validity window elapsed
  Unauthorized,        // no contract/consent/authority covers the request
  NotFound,
  CapacityExceeded,
  Replayed,            // duplicate or replayed artifact rejected
  Reincarnated,        // the counterpart restarted into a new incarnation
  Corrupt,             // integrity check failed
  Incompatible,        // persisted format or protocol version cannot be handled
  Overflow,            // checked arithmetic rejected the input
  Busy,                // the resource is temporarily unavailable
  AlreadyExists,
  Internal,
};

[[nodiscard]] const char* to_string(Outcome outcome) noexcept;
[[nodiscard]] bool is_ok(Outcome outcome) noexcept;
// True only for outcomes under which connectivity may actually be used.
[[nodiscard]] bool is_authorized(Outcome outcome) noexcept;
// True when the outcome means "the truth is not established" rather than "denied".
[[nodiscard]] bool is_indeterminate_family(Outcome outcome) noexcept;
// Parses the canonical upper-case name produced by to_string().
[[nodiscard]] bool outcome_from_string(std::string_view text, Outcome& out) noexcept;

class Status {
 public:
  Status() noexcept = default;
  static Status ok() noexcept { return Status{}; }
  static Status make(Outcome outcome, std::string message);

  [[nodiscard]] Outcome outcome() const noexcept { return outcome_; }
  [[nodiscard]] bool is_ok() const noexcept { return outcome_ == Outcome::Ok; }
  [[nodiscard]] const std::string& message() const noexcept { return message_; }
  [[nodiscard]] std::string to_string() const;

  explicit operator bool() const noexcept { return is_ok(); }

 private:
  Outcome outcome_ = Outcome::Ok;
  std::string message_;
};

template <class T>
class Result {
 public:
  Result(T value) : value_(std::move(value)) {}          // NOLINT(google-explicit-constructor)
  Result(Status status) : value_(std::move(status)) {}   // NOLINT(google-explicit-constructor)

  [[nodiscard]] bool has_value() const noexcept { return std::holds_alternative<T>(value_); }
  explicit operator bool() const noexcept { return has_value(); }

  [[nodiscard]] T value_or(T fallback) const { return has_value() ? std::get<T>(value_) : std::move(fallback); }

  T& value() & { return std::get<T>(value_); }
  const T& value() const& { return std::get<T>(value_); }
  T&& value() && { return std::get<T>(std::move(value_)); }

  [[nodiscard]] const Status& status() const noexcept {
    static const Status kOk{};
    const Status* s = std::get_if<Status>(&value_);
    return s != nullptr ? *s : kOk;
  }

 private:
  std::variant<T, Status> value_;
};

template <>
class Result<void> {
 public:
  Result() = default;
  Result(Status status) : status_(std::move(status)) {}  // NOLINT(google-explicit-constructor)

  [[nodiscard]] bool has_value() const noexcept { return status_.is_ok(); }
  explicit operator bool() const noexcept { return has_value(); }
  [[nodiscard]] const Status& status() const noexcept { return status_; }

 private:
  Status status_;
};

// Convenience constructors that keep call sites short and uniform.
[[nodiscard]] inline Status invalid(std::string message) {
  return Status::make(Outcome::Invalid, std::move(message));
}
[[nodiscard]] inline Status unsupported(std::string message) {
  return Status::make(Outcome::Unsupported, std::move(message));
}
[[nodiscard]] inline Status not_found(std::string message) {
  return Status::make(Outcome::NotFound, std::move(message));
}
[[nodiscard]] inline Status internal_error(std::string message) {
  return Status::make(Outcome::Internal, std::move(message));
}

}  // namespace icf
