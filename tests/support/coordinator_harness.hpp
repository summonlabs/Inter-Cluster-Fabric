// Runs a coordinator on a background thread over a real loopback socket for the tests.
#pragma once

#include <atomic>
#include <map>
#include <memory>
#include <string>
#include <thread>

#include "icf/runtime/coordinator.hpp"
#include "temp_dir.hpp"

namespace icf::test {

class CoordinatorHarness {
 public:
  explicit CoordinatorHarness(const std::string& name, bool durable = false, std::size_t max_connections = 0,
                              Duration idle_deadline = Duration::from_seconds(30),
                              std::map<std::string, std::string> domain_keys = {}) {
    directory_ = std::make_unique<TempDir>(name);
    icf::runtime::Coordinator::Config config;
    config.state_directory = directory_->path();
    config.domain = AuthorityDomainId::parse("test-domain").value();
    config.listen_port = 0;
    config.durable = durable;
    config.agent_idle_deadline = idle_deadline;
    config.domain_keys = std::move(domain_keys);
    if (max_connections != 0) {
      config.max_connections = max_connections;
    }
    Result<std::unique_ptr<icf::runtime::Coordinator>> created =
        icf::runtime::Coordinator::create(config, clock_);
    if (!created) {
      failure_ = created.status().to_string();
      return;
    }
    coordinator_ = std::move(created.value());
    port_ = coordinator_->port();
    ready_.store(false);
    thread_ = std::thread([this]() {
      ready_.store(true);
      (void)coordinator_->serve();
    });
    while (!ready_.load()) {
    }
  }

  ~CoordinatorHarness() {
    if (coordinator_) {
      coordinator_->stop();
    }
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  CoordinatorHarness(const CoordinatorHarness&) = delete;
  CoordinatorHarness& operator=(const CoordinatorHarness&) = delete;

  [[nodiscard]] bool valid() const noexcept { return coordinator_ != nullptr; }
  [[nodiscard]] const std::string& failure() const noexcept { return failure_; }
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] std::string address() const { return "127.0.0.1:" + std::to_string(port_); }
  [[nodiscard]] icf::runtime::Coordinator& coordinator() { return *coordinator_; }
  [[nodiscard]] const icf::runtime::Coordinator& coordinator() const { return *coordinator_; }
  [[nodiscard]] const Clock& clock() const noexcept { return clock_; }
  [[nodiscard]] const std::string& directory() const noexcept { return directory_->path(); }

 private:
  std::unique_ptr<TempDir> directory_;
  icf::SystemClock clock_;
  std::unique_ptr<icf::runtime::Coordinator> coordinator_;
  std::thread thread_;
  std::atomic<bool> ready_{false};
  std::uint16_t port_ = 0;
  std::string failure_;
};

}  // namespace icf::test
