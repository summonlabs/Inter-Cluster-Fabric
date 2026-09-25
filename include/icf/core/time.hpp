// Inter-Cluster Fabric - time and clocks.
//
// Every deadline, validity window, and lease expiry in the runtime reads the injected clock.
// Tests drive a ManualClock so that expiry behavior is deterministic and no test depends on
// wall-clock sleeps.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "icf/core/status.hpp"

namespace icf {

class Duration {
 public:
  constexpr Duration() noexcept = default;

  [[nodiscard]] static constexpr Duration from_nanos(std::int64_t value) noexcept { return Duration(value); }
  [[nodiscard]] static constexpr Duration from_micros(std::int64_t value) noexcept { return Duration(value * 1000); }
  [[nodiscard]] static constexpr Duration from_millis(std::int64_t value) noexcept { return Duration(value * 1000000); }
  [[nodiscard]] static constexpr Duration from_seconds(std::int64_t value) noexcept { return Duration(value * 1000000000); }
  [[nodiscard]] static constexpr Duration from_minutes(std::int64_t value) noexcept {
    return Duration(value * 60000000000);
  }

  [[nodiscard]] static Result<Duration> parse(std::string_view text);

  [[nodiscard]] constexpr std::int64_t nanos() const noexcept { return nanos_; }
  [[nodiscard]] constexpr std::int64_t millis() const noexcept { return nanos_ / 1000000; }
  [[nodiscard]] constexpr double seconds() const noexcept { return static_cast<double>(nanos_) / 1e9; }
  [[nodiscard]] constexpr bool is_zero() const noexcept { return nanos_ == 0; }
  [[nodiscard]] constexpr bool is_negative() const noexcept { return nanos_ < 0; }

  friend constexpr bool operator==(Duration, Duration) noexcept = default;
  friend constexpr auto operator<=>(Duration, Duration) noexcept = default;

 private:
  explicit constexpr Duration(std::int64_t nanos) noexcept : nanos_(nanos) {}
  std::int64_t nanos_ = 0;
};

class Timestamp {
 public:
  constexpr Timestamp() noexcept = default;

  [[nodiscard]] static constexpr Timestamp from_unix_nanos(std::int64_t value) noexcept {
    Timestamp result;
    result.unix_nanos_ = value;
    return result;
  }
  [[nodiscard]] static constexpr Timestamp from_unix_millis(std::int64_t value) noexcept {
    return from_unix_nanos(value * 1000000);
  }

  [[nodiscard]] constexpr std::int64_t unix_nanos() const noexcept { return unix_nanos_; }
  [[nodiscard]] constexpr bool is_zero() const noexcept { return unix_nanos_ == 0; }

  [[nodiscard]] Timestamp plus(Duration delta) const noexcept;
  [[nodiscard]] Duration since(Timestamp earlier) const noexcept;

  [[nodiscard]] std::string to_iso8601() const;
  [[nodiscard]] static Result<Timestamp> parse_iso8601(std::string_view text);

  friend constexpr bool operator==(Timestamp, Timestamp) noexcept = default;
  friend constexpr auto operator<=>(Timestamp, Timestamp) noexcept = default;

 private:
  std::int64_t unix_nanos_ = 0;
};

class Clock {
 public:
  Clock() = default;
  Clock(const Clock&) = delete;
  Clock& operator=(const Clock&) = delete;
  Clock(Clock&&) = delete;
  Clock& operator=(Clock&&) = delete;
  virtual ~Clock() = default;

  [[nodiscard]] virtual Timestamp now() const = 0;
  [[nodiscard]] virtual std::int64_t monotonic_nanos() const = 0;
};

class SystemClock final : public Clock {
 public:
  [[nodiscard]] Timestamp now() const override;
  [[nodiscard]] std::int64_t monotonic_nanos() const override;
};

// Deterministic clock for tests: time only moves when the test moves it.
class ManualClock final : public Clock {
 public:
  ManualClock() = default;
  explicit ManualClock(Timestamp start) : wall_(start) {}

  [[nodiscard]] Timestamp now() const override { return wall_; }
  [[nodiscard]] std::int64_t monotonic_nanos() const override { return monotonic_; }

  void advance(Duration delta) noexcept {
    wall_ = wall_.plus(delta);
    monotonic_ += delta.nanos();
  }
  void set(Timestamp value) noexcept { wall_ = value; }

 private:
  Timestamp wall_{};
  std::int64_t monotonic_ = 0;
};

}  // namespace icf
