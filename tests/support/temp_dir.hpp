// Inter-Cluster Fabric - scratch directories for tests.
#pragma once

#include <filesystem>
#include <string>

#include "icf/core/rng.hpp"

namespace icf::test {

class TempDir {
 public:
  explicit TempDir(const std::string& name) {
    Rng rng(entropy_seed());
    path_ = (std::filesystem::temp_directory_path() /
             ("icf-test-" + name + "-" + std::to_string(rng.next_u64())))
                .string();
    std::filesystem::remove_all(path_);
    std::filesystem::create_directories(path_);
  }

  ~TempDir() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }

  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  [[nodiscard]] const std::string& path() const noexcept { return path_; }
  [[nodiscard]] std::string child(const std::string& name) const { return path_ + "/" + name; }

 private:
  std::string path_;
};

}  // namespace icf::test
