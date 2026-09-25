// Inter-Cluster Fabric - durable file primitives.
//
// Every persisted artifact is written to a temporary file, flushed to stable storage, and then
// atomically renamed into place, so a crash never leaves a half-written artifact at the final
// path. Reads are bounded before allocation.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "icf/core/status.hpp"

namespace icf::store {

[[nodiscard]] bool file_exists(const std::string& path);
[[nodiscard]] Result<std::uint64_t> file_size(const std::string& path);
[[nodiscard]] Status ensure_directory(const std::string& path);
[[nodiscard]] Status remove_file(const std::string& path);
[[nodiscard]] Result<std::vector<std::byte>> read_file_bounded(const std::string& path, std::uint64_t max_bytes);
[[nodiscard]] Status write_file_atomic(const std::string& path, const std::vector<std::byte>& contents);
[[nodiscard]] Status append_file(const std::string& path, const std::vector<std::byte>& contents, bool flush);
[[nodiscard]] Status flush_path(const std::string& path);
// Truncates a file to the given length. Used only for conservative recovery of a torn tail.
[[nodiscard]] Status truncate_file(const std::string& path, std::uint64_t length);
[[nodiscard]] std::string join_path(const std::string& directory, const std::string& name);

}  // namespace icf::store
