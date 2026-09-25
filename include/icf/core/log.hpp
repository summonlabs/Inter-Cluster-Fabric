// Inter-Cluster Fabric - bounded local logging.
//
// The runtime never transmits telemetry. Logs are written to stderr or to a file the
// operator names, one bounded line per event, with no outbound network path.
#pragma once

#include <cstdio>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>

#include "icf/core/status.hpp"
#include "icf/core/time.hpp"

namespace icf {

enum class LogLevel : int {
  Trace = 0,
  Debug = 1,
  Info = 2,
  Warn = 3,
  Error = 4,
  Off = 5,
};

[[nodiscard]] const char* to_string(LogLevel level) noexcept;
[[nodiscard]] bool log_level_from_string(std::string_view text, LogLevel& out) noexcept;

class Logger {
 public:
  static Logger& instance();

  void set_level(LogLevel level) noexcept { level_ = level; }
  [[nodiscard]] LogLevel level() const noexcept { return level_; }
  [[nodiscard]] bool enabled(LogLevel level) const noexcept { return static_cast<int>(level) >= static_cast<int>(level_); }

  void set_stream(std::FILE* stream) noexcept;
  Status set_file(const std::string& path);
  void close_file();

  // The clock is used only for the log timestamp; it may be swapped by tests.
  void set_clock(const Clock* clock) noexcept { clock_ = clock; }

  void write(LogLevel level, std::string_view component, std::string_view message);
  void write_fields(LogLevel level, std::string_view component, std::string_view message,
                    std::initializer_list<std::pair<std::string_view, std::string_view>> fields);

 private:
  Logger() = default;
  ~Logger();

  LogLevel level_ = LogLevel::Info;
  std::FILE* stream_ = nullptr;
  bool owns_stream_ = false;
  const Clock* clock_ = nullptr;
};

// Convenience wrappers: ICF_LOG_INFO("component", "message") and the *_KF variant that
// appends key=value fields.
#define ICF_LOG_TRACE(component, message)   ::icf::Logger::instance().write(::icf::LogLevel::Trace, (component), (message))
#define ICF_LOG_DEBUG(component, message)   ::icf::Logger::instance().write(::icf::LogLevel::Debug, (component), (message))
#define ICF_LOG_INFO(component, message)   ::icf::Logger::instance().write(::icf::LogLevel::Info, (component), (message))
#define ICF_LOG_WARN(component, message)   ::icf::Logger::instance().write(::icf::LogLevel::Warn, (component), (message))
#define ICF_LOG_ERROR(component, message)   ::icf::Logger::instance().write(::icf::LogLevel::Error, (component), (message))

#define ICF_LOG_INFO_KF(component, message, fields)   ::icf::Logger::instance().write_fields(::icf::LogLevel::Info, (component), (message), fields)
#define ICF_LOG_WARN_KF(component, message, fields)   ::icf::Logger::instance().write_fields(::icf::LogLevel::Warn, (component), (message), fields)
#define ICF_LOG_DEBUG_KF(component, message, fields)   ::icf::Logger::instance().write_fields(::icf::LogLevel::Debug, (component), (message), fields)

}  // namespace icf
