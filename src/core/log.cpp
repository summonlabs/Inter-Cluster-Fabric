#include "icf/core/log.hpp"

#include <chrono>
#include <cstring>
#include <mutex>
#include <string>

#include "icf/core/limits.hpp"
#include "icf/core/time.hpp"
#include "icf/core/utf8.hpp"

namespace icf {
namespace {

SystemClock& log_clock() {
  static SystemClock clock;
  return clock;
}

// Leaf lock: the logger never calls back into any other component while holding it, so it
// can never participate in a lock cycle.
std::mutex& logger_mutex() {
  static std::mutex mutex;
  return mutex;
}

// Log output is bounded and control characters are escaped so that a hostile peer cannot
// forge log lines or inject terminal escapes.
std::string sanitize(std::string_view text) {
  const std::string_view limited = text.substr(0, utf8_prefix_length(text, 256));
  std::string out;
  out.reserve(limited.size());
  for (const char c : limited) {
    const auto byte = static_cast<unsigned char>(c);
    if (c == '"' || c == '\\') {
      out.push_back('\\');
      out.push_back(c);
    } else if (byte < 0x20u || byte == 0x7Fu) {
      out.push_back('?');
    } else {
      out.push_back(c);
    }
  }
  return out;
}

}  // namespace

const char* to_string(LogLevel level) noexcept {
  switch (level) {
    case LogLevel::Trace:
      return "TRACE";
    case LogLevel::Debug:
      return "DEBUG";
    case LogLevel::Info:
      return "INFO";
    case LogLevel::Warn:
      return "WARN";
    case LogLevel::Error:
      return "ERROR";
    case LogLevel::Off:
      return "OFF";
  }
  return "OFF";
}

bool log_level_from_string(std::string_view text, LogLevel& out) noexcept {
  if (text == "trace") {
    out = LogLevel::Trace;
  } else if (text == "debug") {
    out = LogLevel::Debug;
  } else if (text == "info") {
    out = LogLevel::Info;
  } else if (text == "warn") {
    out = LogLevel::Warn;
  } else if (text == "error") {
    out = LogLevel::Error;
  } else if (text == "off") {
    out = LogLevel::Off;
  } else {
    return false;
  }
  return true;
}

Logger& Logger::instance() {
  static Logger logger;
  return logger;
}

Logger::~Logger() { close_file(); }

void Logger::set_stream(std::FILE* stream) noexcept {
  std::lock_guard<std::mutex> guard(logger_mutex());
  close_file();
  stream_ = stream;
  owns_stream_ = false;
}

Status Logger::set_file(const std::string& path) {
  std::FILE* file = nullptr;
#if defined(_WIN32)
  if (fopen_s(&file, path.c_str(), "ab") != 0) {
    file = nullptr;
  }
#else
  file = std::fopen(path.c_str(), "ab");
#endif
  if (file == nullptr) {
    return Status::make(Outcome::Internal, "cannot open log file: " + path);
  }
  std::lock_guard<std::mutex> guard(logger_mutex());
  close_file();
  stream_ = file;
  owns_stream_ = true;
  return Status::ok();
}

// Callers hold logger_mutex().
void Logger::close_file() {
  if (stream_ != nullptr && owns_stream_) {
    std::fclose(stream_);
  }
  stream_ = nullptr;
  owns_stream_ = false;
}

void Logger::write(LogLevel level, std::string_view component, std::string_view message) {
  write_fields(level, component, message, {});
}

void Logger::write_fields(LogLevel level, std::string_view component, std::string_view message,
                          std::initializer_list<std::pair<std::string_view, std::string_view>> fields) {
  if (!enabled(level)) {
    return;
  }
  const Clock* clock = clock_ != nullptr ? clock_ : &log_clock();
  const std::string timestamp = clock->now().to_iso8601();

  std::string line;
  line.reserve(256);
  line += timestamp;
  line += " level=";
  line += to_string(level);
  line += " component=";
  line.append(component.substr(0, utf8_prefix_length(component, 64)));
  line += " message=\"";
  line.append(sanitize(message));
  line += '"';
  for (const auto& field : fields) {
    line += ' ';
    line.append(field.first.substr(0, 48));
    line += '=';
    line.append(sanitize(field.second));
  }
  if (line.size() > limits::kMaxLogLineLength) {
    line.resize(utf8_prefix_length(line, limits::kMaxLogLineLength));
  }
  line += '\n';

  std::lock_guard<std::mutex> guard(logger_mutex());
  std::FILE* out = stream_ != nullptr ? stream_ : stderr;
  std::fwrite(line.data(), 1, line.size(), out);
  std::fflush(out);
}

}  // namespace icf
