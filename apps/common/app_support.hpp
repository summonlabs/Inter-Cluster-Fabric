// Inter-Cluster Fabric - shared command-line support for the daemons, the CLI, and the
// benchmark harness. Header-only so each executable stays a single translation unit plus the
// runtime library.
#pragma once

#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "icf/core/config.hpp"
#include "icf/core/log.hpp"
#include "icf/core/status.hpp"
#include "icf/core/time.hpp"
#include "icf/model/records.hpp"

namespace icf::app {

inline std::atomic<bool>& stop_requested() {
  static std::atomic<bool> flag{false};
  return flag;
}

inline void request_stop(int /*signal*/) { stop_requested().store(true); }

inline void install_signal_handlers() {
  std::signal(SIGINT, request_stop);
  std::signal(SIGTERM, request_stop);
#if defined(SIGBREAK)
  std::signal(SIGBREAK, request_stop);
#endif
}

// Option names are normalised so that "--state-dir" and "--state_dir" name the same key. Only the
// leading option name is normalised: everything after the first dot belongs to a structured key
// such as "endpoint.<id>.scope" or "domain_key.<domain>", where a dash may be part of an identity
// and must be preserved exactly.
[[nodiscard]] inline std::string normalize_option(std::string key) {
  const std::size_t dot = key.find('.');
  const std::size_t head_length = dot == std::string::npos ? key.size() : dot;
  for (std::size_t index = 0; index < head_length; ++index) {
    if (key[index] == '-') {
      key[index] = '_';
    }
  }
  return key;
}

[[nodiscard]] inline Result<std::uint64_t> parse_u64(std::string_view text) {
  if (text.empty() || text.size() > 20) {
    return invalid("expected an unsigned decimal integer");
  }
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') {
      return invalid("expected an unsigned decimal integer");
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
    if (value > (UINT64_MAX - digit) / 10u) {
      return Status::make(Outcome::Overflow, "integer does not fit in 64 bits");
    }
    value = value * 10u + digit;
  }
  return value;
}

[[nodiscard]] inline Result<bool> parse_bool(std::string_view text) {
  if (text == "true" || text == "1" || text == "yes" || text == "on") {
    return true;
  }
  if (text == "false" || text == "0" || text == "no" || text == "off") {
    return false;
  }
  return invalid("expected a boolean value");
}

// Parsed command line: normalised option values plus positional arguments.
struct Arguments {
  std::map<std::string, std::string> options;
  std::vector<std::string> positional;

  [[nodiscard]] bool has(std::string_view key) const {
    return options.find(normalize_option(std::string(key))) != options.end();
  }

  [[nodiscard]] std::string get(std::string_view key, std::string fallback = std::string()) const {
    const auto it = options.find(normalize_option(std::string(key)));
    return it == options.end() ? std::move(fallback) : it->second;
  }

  [[nodiscard]] Result<std::uint64_t> get_u64(std::string_view key) const {
    const auto it = options.find(normalize_option(std::string(key)));
    if (it == options.end()) {
      return Status::make(Outcome::NotFound, "missing option --" + std::string(key));
    }
    return parse_u64(it->second);
  }
};

// Parses "--key value", "--key=value", and bare flags. Everything after "--" is positional.
[[nodiscard]] inline Result<Arguments> parse_arguments(int argc, char** argv) {
  Arguments arguments;
  bool positional_only = false;
  for (int index = 1; index < argc; ++index) {
    const std::string token = argv[index];
    if (positional_only) {
      arguments.positional.push_back(token);
      continue;
    }
    if (token == "--") {
      positional_only = true;
      continue;
    }
    if (token.size() > 2 && token[0] == '-' && token[1] == '-') {
      const std::size_t equals = token.find('=');
      if (equals != std::string::npos) {
        arguments.options[normalize_option(token.substr(2, equals - 2))] = token.substr(equals + 1);
        continue;
      }
      const std::string key = normalize_option(token.substr(2));
      if (index + 1 < argc && (argv[index + 1][0] != '-' || argv[index + 1][1] == '\0')) {
        arguments.options[key] = argv[index + 1];
        ++index;
      } else {
        arguments.options[key] = "true";
      }
      continue;
    }
    arguments.positional.push_back(token);
  }
  return arguments;
}

[[nodiscard]] inline LogLevel log_level_from(const Arguments& arguments, LogLevel fallback) {
  const std::string text = arguments.get("log_level");
  LogLevel level = fallback;
  if (!text.empty() && log_level_from_string(text, level)) {
    return level;
  }
  return fallback;
}

// Splits "host:port". Port 0 is allowed and means "let the operating system choose".
[[nodiscard]] inline Result<std::pair<std::string, std::uint16_t>> parse_endpoint(std::string_view text) {
  const std::size_t colon = text.rfind(':');
  if (colon == std::string_view::npos || colon == 0 || colon + 1 >= text.size()) {
    return invalid("expected host:port");
  }
  const std::string host(text.substr(0, colon));
  const std::string port_text(text.substr(colon + 1));
  Result<std::uint64_t> port = parse_u64(port_text);
  if (!port) {
    return port.status();
  }
  if (port.value() > 65535) {
    return invalid("port is out of range");
  }
  if (std::strchr(host.c_str(), '@') != nullptr || std::strchr(host.c_str(), '/') != nullptr) {
    return invalid("host contains characters that are not accepted");
  }
  return std::make_pair(host, static_cast<std::uint16_t>(port.value()));
}

[[nodiscard]] inline Result<std::string> read_text_file(const std::string& path) {
  std::FILE* file = nullptr;
#if defined(_WIN32)
  if (fopen_s(&file, path.c_str(), "rb") != 0) {
    return Status::make(Outcome::NotFound, "cannot open file: " + path);
  }
#else
  file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    return Status::make(Outcome::NotFound, "cannot open file: " + path);
  }
#endif
  std::string contents;
  char buffer[4096];
  std::size_t read = 0;
  while ((read = std::fread(buffer, 1, sizeof(buffer), file)) > 0) {
    contents.append(buffer, read);
  }
  std::fclose(file);
  return contents;
}

// Loads an optional configuration file and merges the command line on top. Command-line values
// win, so an operator can always override a file without editing it.
[[nodiscard]] inline Result<Config> load_config(const Arguments& arguments) {
  Config config;
  const std::string path = arguments.get("config");
  if (!path.empty()) {
    Result<Config> loaded = Config::load_file(path);
    if (!loaded) {
      return loaded.status();
    }
    config = loaded.value();
  }
  for (const auto& entry : arguments.options) {
    if (entry.first == "config" || entry.first == "log_level") {
      continue;
    }
    const Status applied = config.set(entry.first, entry.second);
    if (!applied) {
      return applied;
    }
  }
  return config;
}

[[nodiscard]] inline std::string config_string(const Config& config, const Arguments& arguments,
                                               std::string_view key, std::string fallback) {
  if (arguments.has(key)) {
    return arguments.get(key);
  }
  return config.get_string_or(key, std::move(fallback));
}

[[nodiscard]] inline std::uint64_t config_u64(const Config& config, const Arguments& arguments, std::string_view key,
                                              std::uint64_t fallback) {
  if (arguments.has(key)) {
    Result<std::uint64_t> parsed = parse_u64(arguments.get(key));
    return parsed ? parsed.value() : fallback;
  }
  return config.get_u64_or(key, fallback);
}

[[nodiscard]] inline bool config_bool(const Config& config, const Arguments& arguments, std::string_view key,
                                      bool fallback) {
  if (arguments.has(key)) {
    Result<bool> parsed = parse_bool(arguments.get(key));
    return parsed ? parsed.value() : fallback;
  }
  return config.get_bool_or(key, fallback);
}

// Collects "domain_key.<domain>=<secret>" entries into a map.
[[nodiscard]] inline std::map<std::string, std::string> channel_keys(const Config& config) {
  std::map<std::string, std::string> keys;
  for (const auto& entry : config.raw()) {
    constexpr std::string_view prefix = "domain_key.";
    if (entry.first.size() > prefix.size() && entry.first.compare(0, prefix.size(), prefix) == 0) {
      keys[entry.first.substr(prefix.size())] = entry.second;
    }
  }
  return keys;
}

// Parses endpoint declarations from the configuration:
//   endpoint.<id>.scope = /tenant/a
//   endpoint.<id>.capacity = 4096
//   endpoint.<id>.degraded = true
//   endpoint.<id>.allow = true
[[nodiscard]] inline Result<std::vector<model::EndpointRecord>> parse_endpoints(const Config& config,
                                                                                const ClusterId& cluster) {
  std::vector<model::EndpointRecord> endpoints;
  std::map<std::string, std::size_t> index_by_id;
  constexpr std::string_view prefix = "endpoint.";
  for (const auto& entry : config.raw()) {
    if (entry.first.size() <= prefix.size() || entry.first.compare(0, prefix.size(), prefix) != 0) {
      continue;
    }
    const std::string remainder = entry.first.substr(prefix.size());
    const std::size_t dot = remainder.find('.');
    if (dot == std::string::npos) {
      return invalid("endpoint configuration key must be endpoint.<id>.<field>: " + entry.first);
    }
    const std::string id_text = remainder.substr(0, dot);
    const std::string field = remainder.substr(dot + 1);
    Result<EndpointId> id = EndpointId::parse(id_text);
    if (!id) {
      return id.status();
    }
    std::size_t index = 0;
    const auto existing = index_by_id.find(id_text);
    if (existing == index_by_id.end()) {
      if (endpoints.size() >= limits::kMaxEndpointsPerCluster) {
        return Status::make(Outcome::CapacityExceeded, "too many endpoint scopes declared");
      }
      model::EndpointRecord record;
      record.id = id.value();
      record.cluster = cluster;
      record.state = model::EndpointState::Active;
      record.inter_cluster_allowed = true;
      endpoints.push_back(record);
      index = endpoints.size() - 1;
      index_by_id[id_text] = index;
    } else {
      index = existing->second;
    }
    model::EndpointRecord& record = endpoints[index];
    if (field == "scope") {
      Result<ScopeName> scope = ScopeName::parse(entry.second);
      if (!scope) {
        return scope.status();
      }
      record.scope = scope.value();
    } else if (field == "capacity") {
      Result<std::uint64_t> capacity = parse_u64(entry.second);
      if (!capacity) {
        return capacity.status();
      }
      if (capacity.value() > limits::kMaxCapacity) {
        return Status::make(Outcome::Overflow, "endpoint capacity exceeds the maximum");
      }
      record.capacity = CapacityUnits(capacity.value());
    } else if (field == "degraded") {
      Result<bool> degraded = parse_bool(entry.second);
      if (!degraded) {
        return degraded.status();
      }
      record.permits_degraded = degraded.value();
    } else if (field == "allow") {
      Result<bool> allowed = parse_bool(entry.second);
      if (!allowed) {
        return allowed.status();
      }
      record.inter_cluster_allowed = allowed.value();
    } else {
      return invalid("unknown endpoint configuration field: " + field);
    }
    if (record.scope.empty()) {
      record.scope = ScopeName::parse("/" + id_text).value();
    }
  }
  std::sort(endpoints.begin(), endpoints.end(),
            [](const model::EndpointRecord& a, const model::EndpointRecord& b) { return a.id < b.id; });
  return endpoints;
}

}  // namespace icf::app
