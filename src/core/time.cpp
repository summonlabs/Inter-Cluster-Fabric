#include "icf/core/time.hpp"

#include <chrono>
#include <cstdio>

#include "icf/core/checked.hpp"
#include "icf/core/limits.hpp"

namespace icf {
namespace {

// Days-from-civil inverse (Howard Hinnant's algorithm), used instead of gmtime so that the
// formatting is identical on every platform and independent of the C runtime.
struct CivilDate {
  int year;
  unsigned month;
  unsigned day;
};

CivilDate civil_from_days(std::int64_t days) {
  days += 719468;
  const std::int64_t era = (days >= 0 ? days : days - 146096) / 146097;
  const auto doe = static_cast<std::uint64_t>(days - era * 146097);
  const auto yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  const auto y = static_cast<std::int64_t>(yoe) + era * 400;
  const std::uint64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const std::uint64_t mp = (5 * doy + 2) / 153;
  const std::uint64_t d = doy - (153 * mp + 2) / 5 + 1;
  const std::uint64_t m = mp < 10 ? mp + 3 : mp - 9;
  const std::int64_t year = y + (m <= 2 ? 1 : 0);
  return CivilDate{static_cast<int>(year), static_cast<unsigned>(m), static_cast<unsigned>(d)};
}

}  // namespace

Result<Duration> Duration::parse(std::string_view text) {
  if (text.empty() || text.size() > 24) {
    return invalid("duration must be a number followed by ns, us, ms, s, m, or h");
  }
  std::size_t digits = 0;
  std::uint64_t magnitude = 0;
  while (digits < text.size() && text[digits] >= '0' && text[digits] <= '9') {
    const std::uint64_t digit = static_cast<std::uint64_t>(text[digits] - '0');
    if (!checked::mul_u64(magnitude, 10, magnitude) || !checked::add_u64(magnitude, digit, magnitude)) {
      return Status::make(Outcome::Overflow, "duration magnitude overflows");
    }
    ++digits;
  }
  if (digits == 0) {
    return invalid("duration must begin with a decimal magnitude");
  }
  const std::string_view unit = text.substr(digits);
  std::uint64_t multiplier = 0;
  if (unit == "ns") {
    multiplier = 1;
  } else if (unit == "us") {
    multiplier = 1000;
  } else if (unit == "ms") {
    multiplier = 1000000;
  } else if (unit == "s") {
    multiplier = 1000000000;
  } else if (unit == "m") {
    multiplier = 60000000000ull;
  } else if (unit == "h") {
    multiplier = 3600000000000ull;
  } else {
    return invalid("unrecognised duration unit");
  }
  std::uint64_t nanos = 0;
  if (!checked::mul_u64(magnitude, multiplier, nanos) || nanos > limits::kMaxDurationNanos) {
    return Status::make(Outcome::Overflow, "duration exceeds the maximum supported span");
  }
  return Duration::from_nanos(static_cast<std::int64_t>(nanos));
}

Timestamp Timestamp::plus(Duration delta) const noexcept {
  if (delta.nanos() > 0 && unix_nanos_ > INT64_MAX - delta.nanos()) {
    return Timestamp::from_unix_nanos(INT64_MAX);
  }
  if (delta.nanos() < 0 && unix_nanos_ < INT64_MIN - delta.nanos()) {
    return Timestamp::from_unix_nanos(INT64_MIN);
  }
  return Timestamp::from_unix_nanos(unix_nanos_ + delta.nanos());
}

Duration Timestamp::since(Timestamp earlier) const noexcept { return Duration::from_nanos(unix_nanos_ - earlier.unix_nanos_); }

std::string Timestamp::to_iso8601() const {
  const std::int64_t nanos = unix_nanos_;
  std::int64_t seconds = nanos / 1000000000;
  std::int64_t fraction = nanos % 1000000000;
  if (fraction < 0) {
    fraction += 1000000000;
    seconds -= 1;
  }
  std::int64_t days = seconds / 86400;
  std::int64_t second_of_day = seconds % 86400;
  if (second_of_day < 0) {
    second_of_day += 86400;
    days -= 1;
  }
  const CivilDate date = civil_from_days(days);
  const auto hour = static_cast<unsigned>(second_of_day / 3600);
  const auto minute = static_cast<unsigned>((second_of_day % 3600) / 60);
  const auto second = static_cast<unsigned>(second_of_day % 60);

  char buffer[48] = {};
  std::snprintf(buffer, sizeof(buffer), "%04d-%02u-%02uT%02u:%02u:%02u.%09lldZ", date.year, date.month, date.day,
                hour, minute, second, static_cast<long long>(fraction));
  return std::string(buffer);
}

Result<Timestamp> Timestamp::parse_iso8601(std::string_view text) {
  // Accepts exactly YYYY-MM-DDTHH:MM:SS[.fffffffff]Z.
  if (text.size() < 20 || text.back() != 'Z') {
    return invalid("timestamp must be an ISO-8601 UTC value ending in Z");
  }
  auto read_uint = [&text](std::size_t offset, std::size_t count, std::uint64_t& out) -> bool {
    if (offset + count > text.size()) {
      return false;
    }
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < count; ++i) {
      const char c = text[offset + i];
      if (c < '0' || c > '9') {
        return false;
      }
      value = value * 10 + static_cast<std::uint64_t>(c - '0');
    }
    out = value;
    return true;
  };
  std::uint64_t year = 0;
  std::uint64_t month = 0;
  std::uint64_t day = 0;
  std::uint64_t hour = 0;
  std::uint64_t minute = 0;
  std::uint64_t second = 0;
  std::uint64_t fraction = 0;
  if (text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' || text[16] != ':') {
    return invalid("timestamp separators are malformed");
  }
  if (!read_uint(0, 4, year) || !read_uint(5, 2, month) || !read_uint(8, 2, day) || !read_uint(11, 2, hour) ||
      !read_uint(14, 2, minute) || !read_uint(17, 2, second)) {
    return invalid("timestamp contains a non-digit field");
  }
  std::size_t index = 19;
  if (index < text.size() && text[index] == '.') {
    ++index;
    const std::size_t start = index;
    while (index < text.size() && text[index] >= '0' && text[index] <= '9') {
      ++index;
    }
    const std::size_t digits = index - start;
    if (digits == 0 || digits > 9) {
      return invalid("timestamp fractional seconds must have 1 to 9 digits");
    }
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 9; ++i) {
      value = value * 10 + (i < digits ? static_cast<std::uint64_t>(text[start + i] - '0') : 0);
    }
    fraction = value;
  }
  if (index + 1 != text.size()) {
    return invalid("timestamp has trailing characters");
  }
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60) {
    return invalid("timestamp field is out of range");
  }
  // days_from_civil
  std::int64_t y = static_cast<std::int64_t>(year);
  const std::int64_t m = static_cast<std::int64_t>(month);
  const std::int64_t d = static_cast<std::int64_t>(day);
  y -= m <= 2 ? 1 : 0;
  const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
  const std::int64_t yoe = y - era * 400;
  const std::int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const std::int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  const std::int64_t days = era * 146097 + doe - 719468;

  const std::int64_t seconds = days * 86400 + static_cast<std::int64_t>(hour) * 3600 +
                               static_cast<std::int64_t>(minute) * 60 + static_cast<std::int64_t>(second);
  const std::uint64_t magnitude =
      seconds < 0 ? static_cast<std::uint64_t>(-(seconds + 1)) + 1u : static_cast<std::uint64_t>(seconds);
  std::uint64_t nanos = 0;
  if (!checked::mul_u64(magnitude, 1000000000ull, nanos) || nanos > static_cast<std::uint64_t>(INT64_MAX)) {
    return Status::make(Outcome::Overflow, "timestamp overflows the nanosecond range");
  }
  const std::int64_t total = seconds < 0 ? -static_cast<std::int64_t>(nanos) : static_cast<std::int64_t>(nanos);
  return Timestamp::from_unix_nanos(total + static_cast<std::int64_t>(fraction));
}

Timestamp SystemClock::now() const {
  const auto duration = std::chrono::system_clock::now().time_since_epoch();
  return Timestamp::from_unix_nanos(std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count());
}

std::int64_t SystemClock::monotonic_nanos() const {
  const auto duration = std::chrono::steady_clock::now().time_since_epoch();
  return std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
}

}  // namespace icf
