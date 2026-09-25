#include "icf/core/config.hpp"

#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>

#include "icf/core/checked.hpp"
#include "icf/core/limits.hpp"
#include "icf/core/utf8.hpp"

namespace icf {
namespace {

std::string_view trim(std::string_view text) {
  std::size_t begin = 0;
  std::size_t end = text.size();
  while (begin < end && (text[begin] == ' ' || text[begin] == '\t' || text[begin] == '\r')) {
    ++begin;
  }
  while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t' || text[end - 1] == '\r')) {
    --end;
  }
  return text.substr(begin, end - begin);
}

bool valid_key(std::string_view key) {
  if (key.empty() || key.size() > 64) {
    return false;
  }
  for (const char c : key) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
                    c == '_' || c == '-';
    if (!ok) {
      return false;
    }
  }
  return true;
}

}  // namespace

Result<bool> parse_bool(std::string_view text) {
  if (text == "true" || text == "yes" || text == "on" || text == "1") {
    return true;
  }
  if (text == "false" || text == "no" || text == "off" || text == "0") {
    return false;
  }
  return invalid("expected one of true/false, yes/no, on/off, 1/0");
}

Result<std::uint64_t> parse_u64(std::string_view text) {
  if (text.empty()) {
    return invalid("expected an unsigned decimal integer");
  }
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') {
      return invalid("expected an unsigned decimal integer");
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
    if (!checked::mul_u64(value, 10, value) || !checked::add_u64(value, digit, value)) {
      // All digits but out of range: OVERFLOW is a different answer from INVALID input.
      return Status::make(Outcome::Overflow, "integer does not fit in 64 bits");
    }
  }
  return value;
}

Result<std::int64_t> parse_i64(std::string_view text) {
  if (text.empty()) {
    return invalid("expected a signed decimal integer");
  }
  bool negative = false;
  if (text.front() == '-') {
    negative = true;
    text.remove_prefix(1);
  } else if (text.front() == '+') {
    text.remove_prefix(1);
  }
  Result<std::uint64_t> magnitude = parse_u64(text);
  if (!magnitude) {
    return magnitude.status();
  }
  const std::uint64_t limit = negative ? (static_cast<std::uint64_t>(INT64_MAX) + 1u)
                                       : static_cast<std::uint64_t>(INT64_MAX);
  if (magnitude.value() > limit) {
    return Status::make(Outcome::Overflow, "integer does not fit in 64 bits");
  }
  if (negative) {
    if (magnitude.value() == static_cast<std::uint64_t>(INT64_MAX) + 1u) {
      return INT64_MIN;
    }
    return -static_cast<std::int64_t>(magnitude.value());
  }
  return static_cast<std::int64_t>(magnitude.value());
}

Result<Config> Config::parse(std::string_view text, std::string_view origin) {
  if (!is_valid_utf8(text)) {
    return invalid(std::string(origin) + ": configuration is not valid UTF-8");
  }
  Config config;
  std::size_t line_number = 0;
  std::size_t begin = 0;
  while (begin <= text.size()) {
    const std::size_t end = text.find('\n', begin);
    const std::string_view line = text.substr(begin, end == std::string_view::npos ? std::string_view::npos : end - begin);
    begin = (end == std::string_view::npos) ? text.size() + 1 : end + 1;
    ++line_number;
    if (line_number > limits::kMaxConfigLines) {
      return invalid(std::string(origin) + ": too many configuration lines");
    }
    if (line.size() > limits::kMaxConfigLineLength) {
      return invalid(std::string(origin) + ": configuration line exceeds the maximum length");
    }
    std::string_view content = trim(line);
    if (content.empty() || content.front() == '#') {
      continue;
    }
    const std::size_t equals = content.find('=');
    if (equals == std::string_view::npos) {
      return invalid(std::string(origin) + ": line " + std::to_string(line_number) + " is missing '='");
    }
    const std::string_view key = trim(content.substr(0, equals));
    const std::string_view value = trim(content.substr(equals + 1));
    if (!valid_key(key)) {
      return invalid(std::string(origin) + ": line " + std::to_string(line_number) + " has an invalid key");
    }
    if (value.empty()) {
      return invalid(std::string(origin) + ": line " + std::to_string(line_number) + " has an empty value");
    }
    if (value.size() > limits::kMaxStringField) {
      return invalid(std::string(origin) + ": line " + std::to_string(line_number) + " value is too long");
    }
    if (!config.values_.emplace(std::string(key), std::string(value)).second) {
      return invalid(std::string(origin) + ": duplicate key '" + std::string(key) + "'");
    }
  }
  return config;
}

Result<Config> Config::load_file(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return Status::make(Outcome::NotFound, "cannot open configuration file: " + path);
  }
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  const std::string text = buffer.str();
  if (!stream.good() && !stream.eof()) {
    return Status::make(Outcome::Internal, "failed while reading configuration file: " + path);
  }
  return Config::parse(text, path);
}

bool Config::has(std::string_view key) const { return values_.find(std::string(key)) != values_.end(); }

Status Config::set(std::string key, std::string value) {
  if (!valid_key(key)) {
    return invalid("invalid configuration key: " + key);
  }
  if (value.empty() || value.size() > limits::kMaxStringField) {
    return invalid("configuration value has an invalid length");
  }
  if (!is_valid_utf8(value)) {
    return invalid("configuration value is not valid UTF-8");
  }
  values_[std::move(key)] = std::move(value);
  return Status::ok();
}

Result<std::string> Config::get_string(std::string_view key) const {
  const auto it = values_.find(std::string(key));
  if (it == values_.end()) {
    return Status::make(Outcome::NotFound, "missing configuration key '" + std::string(key) + "'");
  }
  return it->second;
}

Result<std::uint64_t> Config::get_u64(std::string_view key) const {
  Result<std::string> value = get_string(key);
  if (!value) {
    return value.status();
  }
  return parse_u64(value.value());
}

Result<std::int64_t> Config::get_i64(std::string_view key) const {
  Result<std::string> value = get_string(key);
  if (!value) {
    return value.status();
  }
  return parse_i64(value.value());
}

Result<bool> Config::get_bool(std::string_view key) const {
  Result<std::string> value = get_string(key);
  if (!value) {
    return value.status();
  }
  return parse_bool(value.value());
}

Result<Duration> Config::get_duration(std::string_view key) const {
  Result<std::string> value = get_string(key);
  if (!value) {
    return value.status();
  }
  return Duration::parse(value.value());
}

std::string Config::get_string_or(std::string_view key, std::string fallback) const {
  const auto it = values_.find(std::string(key));
  return it == values_.end() ? std::move(fallback) : it->second;
}

std::uint64_t Config::get_u64_or(std::string_view key, std::uint64_t fallback) const {
  Result<std::uint64_t> value = get_u64(key);
  return value ? value.value() : fallback;
}

bool Config::get_bool_or(std::string_view key, bool fallback) const {
  Result<bool> value = get_bool(key);
  return value ? value.value() : fallback;
}

Duration Config::get_duration_or(std::string_view key, Duration fallback) const {
  Result<Duration> value = get_duration(key);
  return value ? value.value() : fallback;
}

Status Config::reject_unknown(const std::vector<std::string_view>& known) const {
  std::set<std::string_view> allowed(known.begin(), known.end());
  for (const auto& entry : values_) {
    if (allowed.find(entry.first) == allowed.end()) {
      return invalid("unrecognised configuration key '" + entry.first + "'");
    }
  }
  return Status::ok();
}

std::vector<std::pair<std::string, std::string>> Config::entries() const {
  std::vector<std::pair<std::string, std::string>> out;
  out.reserve(values_.size());
  for (const auto& entry : values_) {
    out.emplace_back(entry.first, entry.second);
  }
  return out;
}

}  // namespace icf
