// Inter-Cluster Fabric - strongly typed identities and generations.
//
// Cluster, endpoint, edge, contract, grant, incarnation, and generation values are distinct
// types. A generation cannot be passed where an incarnation is expected, an attempt id cannot
// be passed where a grant id is expected, and every parse validates the character set, the
// length, and (for text) the encoding before the value exists.
#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>

#include "icf/core/limits.hpp"
#include "icf/core/status.hpp"

namespace icf {

class Rng;

class Uuid {
 public:
  static constexpr std::size_t kSize = 16;

  Uuid() = default;

  [[nodiscard]] static Uuid random(Rng& rng);
  [[nodiscard]] static Result<Uuid> parse(std::string_view text);
  [[nodiscard]] static Uuid from_bytes(std::span<const std::byte> bytes);
  [[nodiscard]] static Uuid from_random_bytes(std::span<const std::byte> bytes);

  [[nodiscard]] const std::array<std::byte, kSize>& bytes() const noexcept { return bytes_; }
  [[nodiscard]] bool is_nil() const noexcept;
  [[nodiscard]] std::string to_string() const;  // 8-4-4-4-12 lower-case hex
  [[nodiscard]] std::string hex() const;        // 32 lower-case hex characters

  friend bool operator==(const Uuid&, const Uuid&) noexcept = default;
  friend auto operator<=>(const Uuid&, const Uuid&) noexcept = default;

 private:
  std::array<std::byte, kSize> bytes_{};
};

// ---- text identities -------------------------------------------------------------

struct IdCharset {
  static constexpr std::string_view kExtra = "._-";
};
struct ScopeCharset {
  static constexpr std::string_view kExtra = "._-/:@";
};

template <class Tag>
class Name {
 public:
  Name() = default;

  [[nodiscard]] static Result<Name> parse(std::string_view text) {
    if (text.empty()) {
      return invalid("identifier must not be empty");
    }
    if (text.size() > Tag::kMaxLength) {
      return invalid("identifier exceeds the maximum permitted length");
    }
    const auto is_alnum = [](char c) {
      return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    };
    const auto is_extra = [](char c) {
      for (const char extra : Tag::kExtra) {
        if (c == extra) {
          return true;
        }
      }
      return false;
    };
    if (!is_alnum(text.front()) && !(Tag::kAllowLeadingSeparator && is_extra(text.front()))) {
      return invalid("identifier must begin with an alphanumeric character");
    }
    for (const char c : text) {
      if (!is_alnum(c) && !is_extra(c)) {
        return invalid("identifier contains a character outside the permitted set");
      }
    }
    Name result;
    result.value_.assign(text);
    return result;
  }

  // Only for values that were validated on the way in (or generated internally).
  [[nodiscard]] static Name unchecked(std::string text) {
    Name result;
    result.value_ = std::move(text);
    return result;
  }

  [[nodiscard]] const std::string& str() const noexcept { return value_; }
  [[nodiscard]] const char* c_str() const noexcept { return value_.c_str(); }
  [[nodiscard]] bool empty() const noexcept { return value_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return value_.size(); }

  friend bool operator==(const Name&, const Name&) noexcept = default;
  friend auto operator<=>(const Name&, const Name&) noexcept = default;

 private:
  std::string value_;
};

// ---- UUID-derived identities -----------------------------------------------------

template <class Tag>
class StrongUuid {
 public:
  StrongUuid() = default;

  [[nodiscard]] static StrongUuid random(Rng& rng) {
    StrongUuid result;
    result.value_ = Uuid::random(rng);
    return result;
  }
  [[nodiscard]] static Result<StrongUuid> parse(std::string_view text) {
    Result<Uuid> parsed = Uuid::parse(text);
    if (!parsed) {
      return parsed.status();
    }
    StrongUuid result;
    result.value_ = parsed.value();
    return result;
  }
  [[nodiscard]] static StrongUuid from_uuid(Uuid value) {
    StrongUuid result;
    result.value_ = value;
    return result;
  }

  [[nodiscard]] const Uuid& uuid() const noexcept { return value_; }
  [[nodiscard]] bool is_nil() const noexcept { return value_.is_nil(); }
  [[nodiscard]] std::string to_string() const { return value_.to_string(); }

  friend bool operator==(const StrongUuid&, const StrongUuid&) noexcept = default;
  friend auto operator<=>(const StrongUuid&, const StrongUuid&) noexcept = default;

 private:
  Uuid value_;
};

// ---- monotonic counters ----------------------------------------------------------

template <class Tag>
class Counter {
 public:
  using value_type = std::uint64_t;

  constexpr Counter() noexcept = default;
  constexpr explicit Counter(std::uint64_t value) noexcept : value_(value) {}

  [[nodiscard]] static Result<Counter> parse(std::string_view text) {
    if (text.empty() || text.size() > 20) {
      return invalid("counter must be a decimal number");
    }
    std::uint64_t value = 0;
    for (const char c : text) {
      if (c < '0' || c > '9') {
        return invalid("counter must be a decimal number");
      }
      const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
      if (value > (UINT64_MAX - digit) / 10u) {
        return Status::make(Outcome::Overflow, "counter does not fit in 64 bits");
      }
      value = value * 10u + digit;
    }
    return Counter(value);
  }

  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_zero() const noexcept { return value_ == 0; }

  // Returns false when the counter is already at its maximum.
  bool increment() noexcept {
    if (value_ == UINT64_MAX) {
      return false;
    }
    ++value_;
    return true;
  }

  [[nodiscard]] Result<Counter> next() const noexcept {
    Counter result = *this;
    if (!result.increment()) {
      return Status::make(Outcome::Overflow, "counter overflow");
    }
    return result;
  }

  friend constexpr bool operator==(Counter, Counter) noexcept = default;
  friend constexpr auto operator<=>(Counter, Counter) noexcept = default;

 private:
  std::uint64_t value_ = 0;
};

template <class Tag>
[[nodiscard]] Result<Counter<Tag>> add(Counter<Tag> a, Counter<Tag> b) {
  if (a.value() > UINT64_MAX - b.value()) {
    return Status::make(Outcome::Overflow, "counter addition overflow");
  }
  return Counter<Tag>(a.value() + b.value());
}

template <class Tag>
[[nodiscard]] Result<Counter<Tag>> subtract(Counter<Tag> a, Counter<Tag> b) {
  if (b.value() > a.value()) {
    return Status::make(Outcome::Overflow, "counter subtraction underflow");
  }
  return Counter<Tag>(a.value() - b.value());
}

// ---- identity tags ---------------------------------------------------------------

struct ClusterIdTag {
  static constexpr std::string_view kExtra = IdCharset::kExtra;
  static constexpr std::size_t kMaxLength = limits::kMaxNameLength;
  static constexpr bool kAllowLeadingSeparator = false;
};
struct AuthorityDomainIdTag {
  static constexpr std::string_view kExtra = IdCharset::kExtra;
  static constexpr std::size_t kMaxLength = limits::kMaxNameLength;
  static constexpr bool kAllowLeadingSeparator = false;
};
struct EndpointIdTag {
  static constexpr std::string_view kExtra = IdCharset::kExtra;
  static constexpr std::size_t kMaxLength = limits::kMaxNameLength;
  static constexpr bool kAllowLeadingSeparator = false;
};
struct EdgeIdTag {
  static constexpr std::string_view kExtra = IdCharset::kExtra;
  static constexpr std::size_t kMaxLength = limits::kMaxNameLength;
  static constexpr bool kAllowLeadingSeparator = false;
};
struct PathIdTag {
  static constexpr std::string_view kExtra = IdCharset::kExtra;
  static constexpr std::size_t kMaxLength = limits::kMaxNameLength;
  static constexpr bool kAllowLeadingSeparator = false;
};
struct ScopeNameTag {
  static constexpr std::string_view kExtra = ScopeCharset::kExtra;
  static constexpr std::size_t kMaxLength = limits::kMaxScopeLength;
  // A scope is a path-like name, so it may begin with a separator.
  static constexpr bool kAllowLeadingSeparator = true;
};

struct IncarnationIdTag {};
struct ContractIdTag {};
struct GrantIdTag {};
struct AttemptIdTag {};
struct SessionTokenTag {};
struct ReservationIdTag {};

struct GenerationTag {};
struct PolicyGenerationTag {};
struct RevisionTag {};
struct SequenceTag {};
struct TermTag {};
struct CapacityUnitsTag {};

using ClusterId = Name<ClusterIdTag>;
using AuthorityDomainId = Name<AuthorityDomainIdTag>;
using EndpointId = Name<EndpointIdTag>;
using EdgeId = Name<EdgeIdTag>;
using PathId = Name<PathIdTag>;
using ScopeName = Name<ScopeNameTag>;

using IncarnationId = StrongUuid<IncarnationIdTag>;
using ContractId = StrongUuid<ContractIdTag>;
using GrantId = StrongUuid<GrantIdTag>;
using AttemptId = StrongUuid<AttemptIdTag>;
using SessionToken = StrongUuid<SessionTokenTag>;
using ReservationId = StrongUuid<ReservationIdTag>;

using Generation = Counter<GenerationTag>;
using PolicyGeneration = Counter<PolicyGenerationTag>;
using Revision = Counter<RevisionTag>;
using Sequence = Counter<SequenceTag>;
using Term = Counter<TermTag>;
using CapacityUnits = Counter<CapacityUnitsTag>;

}  // namespace icf

namespace std {

template <class Tag>
struct hash<icf::Name<Tag>> {
  std::size_t operator()(const icf::Name<Tag>& value) const noexcept {
    return std::hash<std::string>{}(value.str());
  }
};

template <class Tag>
struct hash<icf::StrongUuid<Tag>> {
  std::size_t operator()(const icf::StrongUuid<Tag>& value) const noexcept {
    return std::hash<std::string>{}(value.to_string());
  }
};

template <>
struct hash<icf::Uuid> {
  std::size_t operator()(const icf::Uuid& value) const noexcept {
    std::size_t seed = 1469598103934665603ull;
    for (const std::byte byte : value.bytes()) {
      seed ^= static_cast<std::size_t>(std::to_integer<std::uint8_t>(byte));
      seed *= 1099511628211ull;
    }
    return seed;
  }
};

template <class Tag>
struct hash<icf::Counter<Tag>> {
  std::size_t operator()(const icf::Counter<Tag>& value) const noexcept {
    return std::hash<std::uint64_t>{}(value.value());
  }
};

}  // namespace std
