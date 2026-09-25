#include "icf/store/file_util.hpp"

#include <cstdio>
#include <cstring>
#include <string>

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "icf/core/checked.hpp"
#include "icf/core/limits.hpp"

namespace icf::store {
namespace {

#if defined(_WIN32)
std::wstring to_wide(const std::string& text) {
  if (text.empty()) {
    return std::wstring();
  }
  const int needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
  if (needed <= 0) {
    return std::wstring();
  }
  std::wstring wide(static_cast<std::size_t>(needed), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), wide.data(), needed);
  return wide;
}
#endif

Status to_status(const std::string& what, const std::string& path) {
  return Status::make(Outcome::Internal, what + ": " + path);
}

}  // namespace

std::string join_path(const std::string& directory, const std::string& name) {
  if (directory.empty()) {
    return name;
  }
  const char last = directory.back();
  if (last == '/' || last == '\\') {
    return directory + name;
  }
  return directory + "/" + name;
}

bool file_exists(const std::string& path) {
#if defined(_WIN32)
  const DWORD attributes = GetFileAttributesW(to_wide(path).c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
#else
  struct stat info {};
  return ::stat(path.c_str(), &info) == 0 && S_ISREG(info.st_mode);
#endif
}

Result<std::uint64_t> file_size(const std::string& path) {
#if defined(_WIN32)
  WIN32_FILE_ATTRIBUTE_DATA data {};
  if (GetFileAttributesExW(to_wide(path).c_str(), GetFileExInfoStandard, &data) == 0) {
    return Status::make(Outcome::NotFound, "cannot stat file: " + path);
  }
  const std::uint64_t size = (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
  return size;
#else
  struct stat info {};
  if (::stat(path.c_str(), &info) != 0) {
    return Status::make(Outcome::NotFound, "cannot stat file: " + path);
  }
  return static_cast<std::uint64_t>(info.st_size);
#endif
}

Status ensure_directory(const std::string& path) {
  if (path.empty()) {
    return invalid("directory path is empty");
  }
#if defined(_WIN32)
  const std::wstring wide = to_wide(path);
  if (CreateDirectoryW(wide.c_str(), nullptr) != 0) {
    return Status::ok();
  }
  const DWORD error = GetLastError();
  if (error == ERROR_ALREADY_EXISTS) {
    const DWORD attributes = GetFileAttributesW(wide.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
      return Status::ok();
    }
    return Status::make(Outcome::AlreadyExists, "path exists and is not a directory: " + path);
  }
  // Create intermediate directories one component at a time.
  const std::size_t separator = path.find_last_of("/\\");
  if (separator != std::string::npos && separator > 0) {
    const Status parent = ensure_directory(path.substr(0, separator));
    if (!parent) {
      return parent;
    }
    if (CreateDirectoryW(wide.c_str(), nullptr) != 0 || GetLastError() == ERROR_ALREADY_EXISTS) {
      return Status::ok();
    }
  }
  return to_status("cannot create directory", path);
#else
  if (::mkdir(path.c_str(), 0777) == 0) {
    return Status::ok();
  }
  if (errno == EEXIST) {
    struct stat info {};
    if (::stat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode)) {
      return Status::ok();
    }
    return Status::make(Outcome::AlreadyExists, "path exists and is not a directory: " + path);
  }
  const std::size_t separator = path.find_last_of('/');
  if (separator != std::string::npos && separator > 0) {
    const Status parent = ensure_directory(path.substr(0, separator));
    if (!parent) {
      return parent;
    }
    if (::mkdir(path.c_str(), 0777) == 0) {
      return Status::ok();
    }
  }
  return to_status("cannot create directory", path);
#endif
}

Status remove_file(const std::string& path) {
  if (!file_exists(path)) {
    return Status::ok();
  }
#if defined(_WIN32)
  if (DeleteFileW(to_wide(path).c_str()) == 0) {
    return to_status("cannot remove file", path);
  }
#else
  if (::unlink(path.c_str()) != 0) {
    return to_status("cannot remove file", path);
  }
#endif
  return Status::ok();
}

Result<std::vector<std::byte>> read_file_bounded(const std::string& path, std::uint64_t max_bytes) {
  Result<std::uint64_t> size = file_size(path);
  if (!size) {
    return size.status();
  }
  if (size.value() > max_bytes) {
    return Status::make(Outcome::CapacityExceeded, "file exceeds the configured maximum size: " + path);
  }
  std::size_t length = 0;
  if (!checked::to_size(size.value(), length)) {
    return Status::make(Outcome::Overflow, "file size does not fit in the platform size type");
  }
  std::FILE* file = nullptr;
#if defined(_WIN32)
  if (fopen_s(&file, path.c_str(), "rb") != 0) {
    file = nullptr;
  }
#else
  file = std::fopen(path.c_str(), "rb");
#endif
  if (file == nullptr) {
    return Status::make(Outcome::NotFound, "cannot open file: " + path);
  }
  std::vector<std::byte> contents(length);
  std::size_t read = 0;
  if (length > 0) {
    read = std::fread(contents.data(), 1, length, file);
  }
  const bool failed = read != length;
  std::fclose(file);
  if (failed) {
    return Status::make(Outcome::Internal, "short read while loading: " + path);
  }
  return contents;
}

Status write_file_atomic(const std::string& path, const std::vector<std::byte>& contents) {
  const std::string temporary = path + ".tmp";
  std::FILE* file = nullptr;
#if defined(_WIN32)
  if (fopen_s(&file, temporary.c_str(), "wb") != 0) {
    file = nullptr;
  }
#else
  file = std::fopen(temporary.c_str(), "wb");
#endif
  if (file == nullptr) {
    return to_status("cannot create file", temporary);
  }
  if (!contents.empty() && std::fwrite(contents.data(), 1, contents.size(), file) != contents.size()) {
    std::fclose(file);
    (void)remove_file(temporary);
    return to_status("short write while saving", temporary);
  }
  if (std::fflush(file) != 0) {
    std::fclose(file);
    (void)remove_file(temporary);
    return to_status("flush failed while saving", temporary);
  }
#if defined(_WIN32)
  if (_commit(_fileno(file)) != 0) {
    std::fclose(file);
    (void)remove_file(temporary);
    return to_status("commit failed while saving", temporary);
  }
#else
  if (::fsync(fileno(file)) != 0) {
    std::fclose(file);
    (void)remove_file(temporary);
    return to_status("fsync failed while saving", temporary);
  }
#endif
  std::fclose(file);
#if defined(_WIN32)
  if (MoveFileExW(to_wide(temporary).c_str(), to_wide(path).c_str(),
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    (void)remove_file(temporary);
    return to_status("atomic rename failed", path);
  }
#else
  if (::rename(temporary.c_str(), path.c_str()) != 0) {
    (void)remove_file(temporary);
    return to_status("atomic rename failed", path);
  }
#endif
  return Status::ok();
}

Status append_file(const std::string& path, const std::vector<std::byte>& contents, bool flush) {
  if (contents.empty()) {
    return Status::ok();
  }
  std::FILE* file = nullptr;
#if defined(_WIN32)
  if (fopen_s(&file, path.c_str(), "ab") != 0) {
    file = nullptr;
  }
#else
  file = std::fopen(path.c_str(), "ab");
#endif
  if (file == nullptr) {
    return to_status("cannot open file for append", path);
  }
  const bool short_write = std::fwrite(contents.data(), 1, contents.size(), file) != contents.size();
  const bool flush_failed = std::fflush(file) != 0;
  bool commit_failed = false;
  if (flush && !short_write && !flush_failed) {
#if defined(_WIN32)
    commit_failed = _commit(_fileno(file)) != 0;
#else
    commit_failed = ::fsync(fileno(file)) != 0;
#endif
  }
  std::fclose(file);
  if (short_write) {
    return to_status("short append", path);
  }
  if (flush_failed || commit_failed) {
    return to_status("durable append failed", path);
  }
  return Status::ok();
}

Status flush_path(const std::string& path) {
  std::FILE* file = nullptr;
#if defined(_WIN32)
  if (fopen_s(&file, path.c_str(), "rb+") != 0) {
    file = nullptr;
  }
#else
  file = std::fopen(path.c_str(), "rb+");
#endif
  if (file == nullptr) {
    return to_status("cannot open file to flush", path);
  }
#if defined(_WIN32)
  const bool failed = _commit(_fileno(file)) != 0;
#else
  const bool failed = ::fsync(fileno(file)) != 0;
#endif
  std::fclose(file);
  return failed ? to_status("flush failed", path) : Status::ok();
}

Status truncate_file(const std::string& path, std::uint64_t length) {
#if defined(_WIN32)
  std::FILE* file = nullptr;
  if (fopen_s(&file, path.c_str(), "rb+") != 0) {
    file = nullptr;
  }
  if (file == nullptr) {
    return to_status("cannot open file to truncate", path);
  }
  const bool failed = _chsize_s(_fileno(file), static_cast<__int64>(length)) != 0;
  if (!failed) {
    (void)_commit(_fileno(file));
  }
  std::fclose(file);
#else
  if (::truncate(path.c_str(), static_cast<off_t>(length)) != 0) {
    return to_status("cannot truncate file", path);
  }
  const int descriptor = ::open(path.c_str(), O_RDWR);
  if (descriptor >= 0) {
    (void)::fsync(descriptor);
    (void)::close(descriptor);
  }
  const bool failed = false;
#endif
  return failed ? to_status("truncate failed", path) : Status::ok();
}

}  // namespace icf::store
