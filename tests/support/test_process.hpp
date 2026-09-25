// Spawning and killing real operating-system processes for the multiprocess tests.
//
// Threads are not multiprocess proof: every distributed claim in this repository is verified with
// independent processes over a real framed transport on loopback TCP, and the kill/restart
// scenarios use a hard process termination, not a cooperative shutdown.
//
// Only the Windows path is built and exercised by the recorded verification runs; the POSIX path
// is provided for portability and is marked UNVERIFIED in docs/VALIDATION.md.
#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "icf/core/status.hpp"
#include "icf/store/file_util.hpp"

namespace icf::test {

// Quotes one argument for CreateProcess/execv style command lines.
[[nodiscard]] inline std::string quote_argument(const std::string& argument) {
  std::string quoted = "\"";
  for (const char c : argument) {
    if (c == '"') {
      quoted += "\\\"";
    } else {
      quoted += c;
    }
  }
  quoted += '"';
  return quoted;
}

class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess() { terminate(); }

  ChildProcess(ChildProcess&& other) noexcept { *this = std::move(other); }
  ChildProcess& operator=(ChildProcess&& other) noexcept {
    if (this != &other) {
      terminate();
      handle_ = other.handle_;
      process_id_ = other.process_id_;
      running_ = other.running_;
      log_path_ = std::move(other.log_path_);
      other.handle_ = 0;
      other.process_id_ = 0;
      other.running_ = false;
    }
    return *this;
  }
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  [[nodiscard]] static Result<ChildProcess> spawn(const std::string& executable,
                                                  const std::vector<std::string>& arguments,
                                                  const std::string& working_directory,
                                                  const std::string& log_path) {
    ChildProcess process;
    process.log_path_ = log_path;
#if defined(_WIN32)
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    const std::wstring wide_log = widen(log_path);
    HANDLE log = CreateFileW(wide_log.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log == INVALID_HANDLE_VALUE) {
      return Status::make(Outcome::Internal, "cannot open the child log file");
    }
    std::string command = quote_argument(executable);
    for (const std::string& argument : arguments) {
      command += ' ';
      command += quote_argument(argument);
    }
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = log;
    startup.hStdError = log;
    startup.hStdInput = nullptr;
    PROCESS_INFORMATION information{};
    std::wstring wide_command = widen(command);
    const std::wstring wide_directory = widen(working_directory);
    const BOOL created =
        CreateProcessW(nullptr, wide_command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                       wide_directory.empty() ? nullptr : wide_directory.c_str(), &startup, &information);
    CloseHandle(log);
    if (created == 0) {
      return Status::make(Outcome::Internal, "cannot start child process: " + executable);
    }
    CloseHandle(information.hThread);
    process.handle_ = reinterpret_cast<std::uintptr_t>(information.hProcess);
    process.process_id_ = information.dwProcessId;
    process.running_ = true;
    return process;
#else
    const pid_t child = ::fork();
    if (child < 0) {
      return Status::make(Outcome::Internal, "cannot fork");
    }
    if (child == 0) {
      const int log = ::open(log_path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
      if (log >= 0) {
        (void)::dup2(log, STDOUT_FILENO);
        (void)::dup2(log, STDERR_FILENO);
        (void)::close(log);
      }
      if (!working_directory.empty()) {
        (void)::chdir(working_directory.c_str());
      }
      std::vector<char*> argv;
      argv.push_back(const_cast<char*>(executable.c_str()));
      for (const std::string& argument : arguments) {
        argv.push_back(const_cast<char*>(argument.c_str()));
      }
      argv.push_back(nullptr);
      ::execv(executable.c_str(), argv.data());
      ::_exit(127);
    }
    process.process_id_ = static_cast<std::uint32_t>(child);
    process.running_ = true;
    return process;
#endif
  }

  [[nodiscard]] bool running() {
    if (!running_) {
      return false;
    }
    if (wait_for_exit(Duration::from_nanos(0)).has_value()) {
      return false;
    }
    return true;
  }

  // Bounded wait. A child that is still alive when the bound elapses is reported as
  // UNREACHABLE - the caller decides what that means; it is never silently treated as success.
  [[nodiscard]] Result<int> wait_for_exit(Duration timeout) {
    if (!running_) {
      return exit_code_;
    }
#if defined(_WIN32)
    if (handle_ == 0) {
      return Status::make(Outcome::Internal, "child handle is not open");
    }
    const DWORD milliseconds = timeout.nanos() <= 0 ? 0 : static_cast<DWORD>(timeout.nanos() / 1000000);
    const DWORD waited = WaitForSingleObject(reinterpret_cast<HANDLE>(handle_), milliseconds);
    if (waited == WAIT_TIMEOUT) {
      return Status::make(Outcome::Unreachable, "the child process is still running");
    }
    DWORD code = 0;
    if (GetExitCodeProcess(reinterpret_cast<HANDLE>(handle_), &code) == 0) {
      return Status::make(Outcome::Internal, "cannot read the child exit code");
    }
    CloseHandle(reinterpret_cast<HANDLE>(handle_));
    handle_ = 0;
    running_ = false;
    exit_code_ = static_cast<int>(code);
    return exit_code_;
#else
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::nanoseconds(timeout.nanos());
    for (;;) {
      int status = 0;
      const pid_t result = ::waitpid(static_cast<pid_t>(process_id_), &status, WNOHANG);
      if (result == static_cast<pid_t>(process_id_)) {
        running_ = false;
        exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        return exit_code_;
      }
      if (std::chrono::steady_clock::now() >= deadline) {
        return Status::make(Outcome::Unreachable, "the child process is still running");
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
#endif
  }

  // Hard termination: the equivalent of "kill -9" for the purposes of the restart tests.
  void terminate() {
    if (!running_) {
      return;
    }
#if defined(_WIN32)
    if (handle_ != 0) {
      (void)TerminateProcess(reinterpret_cast<HANDLE>(handle_), 137);
      (void)WaitForSingleObject(reinterpret_cast<HANDLE>(handle_), 5000);
      CloseHandle(reinterpret_cast<HANDLE>(handle_));
      handle_ = 0;
    }
#else
    (void)::kill(static_cast<pid_t>(process_id_), SIGKILL);
    int status = 0;
    (void)::waitpid(static_cast<pid_t>(process_id_), &status, 0);
#endif
    running_ = false;
  }

  [[nodiscard]] std::uint32_t process_id() const noexcept { return process_id_; }
  [[nodiscard]] const std::string& log_path() const noexcept { return log_path_; }

  [[nodiscard]] std::string log_contents() const {
    Result<std::vector<std::byte>> bytes = store::read_file_bounded(log_path_, 1u << 20);
    if (!bytes) {
      return std::string();
    }
    return std::string(reinterpret_cast<const char*>(bytes.value().data()), bytes.value().size());
  }

 private:
#if defined(_WIN32)
  static std::wstring widen(const std::string& text) {
    if (text.empty()) {
      return std::wstring();
    }
    const int needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring wide(static_cast<std::size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), wide.data(), needed);
    return wide;
  }
  std::uintptr_t handle_ = 0;
#else
  static std::wstring widen(const std::string&) { return std::wstring(); }
#endif
  std::uint32_t process_id_ = 0;
  bool running_ = false;
  int exit_code_ = 0;
  std::string log_path_;
};

// Waits for a file to appear, with a bounded wait. Returns false when the bound elapses.
[[nodiscard]] inline bool wait_for_file(const std::string& path, Duration timeout) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::nanoseconds(timeout.nanos());
  while (std::chrono::steady_clock::now() < deadline) {
    if (store::file_exists(path)) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return store::file_exists(path);
}

[[nodiscard]] inline Result<std::map<std::string, std::string>> parse_key_values(const std::string& path) {
  Result<std::vector<std::byte>> bytes = store::read_file_bounded(path, 1u << 16);
  if (!bytes) {
    return bytes.status();
  }
  const std::string text(reinterpret_cast<const char*>(bytes.value().data()), bytes.value().size());
  std::map<std::string, std::string> values;
  std::size_t begin = 0;
  while (begin < text.size()) {
    const std::size_t end = text.find('\n', begin);
    const std::string line = text.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
    const std::size_t equals = line.find('=');
    if (equals != std::string::npos) {
      values[line.substr(0, equals)] = line.substr(equals + 1);
    }
    if (end == std::string::npos) {
      break;
    }
    begin = end + 1;
  }
  return values;
}

// A readiness file is only ready once its content parses and carries a port. Waiting for the file
// to merely exist races with the writer: an empty or half-written file is not readiness.
[[nodiscard]] inline Result<std::map<std::string, std::string>> wait_for_ready_file(const std::string& path,
                                                                                   Duration timeout) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::nanoseconds(timeout.nanos());
  Status last = Status::make(Outcome::Indeterminate, "the readiness file has not appeared");
  for (;;) {
    Result<std::map<std::string, std::string>> values = parse_key_values(path);
    if (values && values.value().find("port") != values.value().end()) {
      return values;
    }
    last = values ? Status::make(Outcome::Incomplete, "the readiness file carries no port yet")
                  : values.status();
    if (std::chrono::steady_clock::now() >= deadline) {
      return last;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
}


// Runs a command to completion and returns its exit code and combined output.
[[nodiscard]] inline Result<std::pair<int, std::string>> run_command(const std::string& executable,
                                                                     const std::vector<std::string>& arguments,
                                                                     Duration timeout,
                                                                     const std::string& working_directory) {
  const std::string log_path = working_directory + "/command.log";
  (void)store::remove_file(log_path);
  Result<ChildProcess> child = ChildProcess::spawn(executable, arguments, working_directory, log_path);
  if (!child) {
    return child.status();
  }
  Result<int> code = child.value().wait_for_exit(timeout);
  if (!code) {
    child.value().terminate();
    return code.status();
  }
  return std::make_pair(code.value(), child.value().log_contents());
}

}  // namespace icf::test
