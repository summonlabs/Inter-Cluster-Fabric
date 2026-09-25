// Inter-Cluster Fabric - bounded configuration files.
//
// Format: one "key = value" pair per line, '#' starts a comment. Unknown keys are an error:
// a typo in an operator configuration file must not silently disable a safety check.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "icf/core/status.hpp"
#include "icf/core/time.hpp"

namespace icf {

class Config {
 public:
  Config() = default;

  [[nodiscard]] static Result<Config> parse(std::string_view text, std::string_view origin);
  [[nodiscard]] static Result<Config> load_file(const std::string& path);

  [[nodiscard]] bool has(std::string_view key) const;
  // Sets or replaces one entry. Used to apply command-line overrides on top of a file.
  [[nodiscard]] Status set(std::string key, std::string value);
  [[nodiscard]] bool empty() const noexcept { return values_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return values_.size(); }

  [[nodiscard]] Result<std::string> get_string(std::string_view key) const;
  [[nodiscard]] Result<std::uint64_t> get_u64(std::string_view key) const;
  [[nodiscard]] Result<std::int64_t> get_i64(std::string_view key) const;
  [[nodiscard]] Result<bool> get_bool(std::string_view key) const;
  [[nodiscard]] Result<Duration> get_duration(std::string_view key) const;

  [[nodiscard]] std::string get_string_or(std::string_view key, std::string fallback) const;
  [[nodiscard]] std::uint64_t get_u64_or(std::string_view key, std::uint64_t fallback) const;
  [[nodiscard]] bool get_bool_or(std::string_view key, bool fallback) const;
  [[nodiscard]] Duration get_duration_or(std::string_view key, Duration fallback) const;

  // Rejects any key that the caller does not recognise.
  [[nodiscard]] Status reject_unknown(const std::vector<std::string_view>& known) const;

  [[nodiscard]] std::vector<std::pair<std::string, std::string>> entries() const;
  [[nodiscard]] const std::map<std::string, std::string>& raw() const noexcept { return values_; }

 private:
  std::map<std::string, std::string> values_;
};

[[nodiscard]] Result<bool> parse_bool(std::string_view text);
[[nodiscard]] Result<std::uint64_t> parse_u64(std::string_view text);
[[nodiscard]] Result<std::int64_t> parse_i64(std::string_view text);

}  // namespace icf
