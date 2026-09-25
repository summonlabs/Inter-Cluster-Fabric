// A fleet of real daemon processes for the multiprocess tests.
//
// The coordinator and every cluster agent run as separate operating-system processes, talk over
// real loopback TCP with the framed transport, and are killed with a hard process termination
// when a test needs to observe a reincarnation.
#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "harness.hpp"
#include "icf/client/client.hpp"
#include "icf/core/rng.hpp"
#include "temp_dir.hpp"
#include "test_process.hpp"

namespace icf::test {

struct AgentSpec {
  std::string cluster;
  std::string domain;
  std::uint64_t generation = 1;
  std::uint64_t policy_generation = 1;
  std::string state = "active";
  std::vector<std::string> endpoint_lines;  // "endpoint.<id>.scope = /scope" style
  std::string shared_key;
};

class Fleet {
 public:
  explicit Fleet(const std::string& name) {
    directory_ = std::make_unique<TempDir>(name);
    bin_dir_ = ICF_BIN_DIR;
    clock_ = std::make_unique<icf::SystemClock>();
  }

  ~Fleet() {
    for (auto& entry : agents_) {
      entry.second.process.terminate();
    }
    coordinator_.terminate();
  }

  Fleet(const Fleet&) = delete;
  Fleet& operator=(const Fleet&) = delete;

  [[nodiscard]] const std::string& root() const noexcept { return directory_->path(); }
  [[nodiscard]] std::uint16_t coordinator_port() const noexcept { return coordinator_port_; }
  [[nodiscard]] icf::Term coordinator_term() const noexcept { return coordinator_term_; }
  [[nodiscard]] const std::string& last_error() const noexcept { return last_error_; }
  [[nodiscard]] bool coordinator_running() { return coordinator_.running(); }

  [[nodiscard]] std::string executable(const std::string& name) const { return bin_dir_ + "/" + name; }

  [[nodiscard]] Status write_file(const std::string& name, const std::string& contents) {
    const std::string path = root() + "/" + name;
    std::vector<std::byte> bytes(reinterpret_cast<const std::byte*>(contents.data()),
                                 reinterpret_cast<const std::byte*>(contents.data()) + contents.size());
    return icf::store::write_file_atomic(path, bytes);
  }

  [[nodiscard]] Result<std::uint16_t> start_coordinator(const std::string& domain = "domain-north",
                                                        const std::string& state_subdir = "coordinator") {
    const std::string state_dir = root() + "/" + state_subdir;
    const std::string ready = state_dir + "/ready";
    (void)icf::store::remove_file(ready);
    // A restart must come back on the same address: the cluster agents reconnect to the address
    // they were configured with, exactly as they would in a deployment.
    const std::string listen = "127.0.0.1:" + std::to_string(coordinator_port_);
    std::vector<std::string> arguments{"--state-dir", state_dir, "--domain", domain, "--listen", listen,
                                       "--ready-file", ready, "--log-level", "info"};
    Result<ChildProcess> child =
        ChildProcess::spawn(executable("icfd"), arguments, root(), root() + "/coordinator.log");
    if (!child) {
      return set_error(child.status());
    }
    coordinator_ = std::move(child.value());
    Result<std::map<std::string, std::string>> values = wait_for_ready_file(ready, Duration::from_seconds(20));
    if (!values) {
      last_error_ = "the coordinator did not become ready (" + values.status().to_string() +
                    "); log:\n" + coordinator_.log_contents();
      return Status::make(values.status().outcome(), last_error_);
    }
    const auto port = values.value().find("port");
    const auto term = values.value().find("term");
    if (port == values.value().end()) {
      return set_error(Status::make(Outcome::Internal, "the readiness file has no port"));
    }
    coordinator_port_ = static_cast<std::uint16_t>(std::strtoul(port->second.c_str(), nullptr, 10));
    coordinator_term_ = icf::Term(term == values.value().end() ? 1 : std::strtoull(term->second.c_str(), nullptr, 10));
    return coordinator_port_;
  }

  [[nodiscard]] Status kill_coordinator() {
    if (!coordinator_.running()) {
      return Status::make(Outcome::NotFound, "the coordinator is not running");
    }
    coordinator_.terminate();
    if (coordinator_.running()) {
      return Status::make(Outcome::Internal, "the coordinator survived a hard termination");
    }
    // The bound port is kept: a restart comes back on the same address, which is what the cluster
    // agents are configured with.
    return Status::ok();
  }

  [[nodiscard]] Result<std::uint16_t> start_agent(const AgentSpec& spec) {
    const std::string state_dir = root() + "/agent-" + spec.cluster;
    const std::string ready = state_dir + "/ready";
    (void)icf::store::remove_file(ready);
    std::string config_text = "cluster = " + spec.cluster + "\n";
    config_text += "domain = " + spec.domain + "\n";
    config_text += "state_dir = " + state_dir + "\n";
    config_text += "coordinator = 127.0.0.1:" + std::to_string(coordinator_port_) + "\n";
    config_text += "generation = " + std::to_string(spec.generation) + "\n";
    config_text += "policy-generation = " + std::to_string(spec.policy_generation) + "\n";
    config_text += "state = " + spec.state + "\n";
    config_text += "ready_file = " + ready + "\n";
    if (!spec.shared_key.empty()) {
      config_text += "shared-key = " + spec.shared_key + "\n";
    }
    for (const std::string& line : spec.endpoint_lines) {
      config_text += line + "\n";
    }
    const std::string config_path = root() + "/agent-" + spec.cluster + ".conf";
    const Status written = write_file("agent-" + spec.cluster + ".conf", config_text);
    if (!written) {
      return set_error(written);
    }
    std::vector<std::string> arguments{"--config", config_path, "--log-level", "info"};
    Result<ChildProcess> child =
        ChildProcess::spawn(executable("icfclusterd"), arguments, root(), root() + "/" + spec.cluster + ".log");
    if (!child) {
      return set_error(child.status());
    }
    auto& entry = agents_[spec.cluster];
    entry.process.terminate();
    entry.process = std::move(child.value());
    entry.incarnation = icf::IncarnationId{};
    Result<std::map<std::string, std::string>> values = wait_for_ready_file(ready, Duration::from_seconds(20));
    if (!values) {
      last_error_ = "agent " + spec.cluster + " did not become ready (" + values.status().to_string() +
                    "); log:\n" + entry.process.log_contents();
      return Status::make(values.status().outcome(), last_error_);
    }
    const auto port = values.value().find("port");
    if (port == values.value().end()) {
      return set_error(Status::make(Outcome::Internal, "the agent readiness file has no control port"));
    }
    entry.control_port = static_cast<std::uint16_t>(std::strtoul(port->second.c_str(), nullptr, 10));
    const auto generation = values.value().find("generation");
    if (generation != values.value().end()) {
      entry.generation = std::strtoull(generation->second.c_str(), nullptr, 10);
    }
    const auto incarnation = values.value().find("incarnation");
    if (incarnation != values.value().end()) {
      Result<icf::IncarnationId> parsed = icf::IncarnationId::parse(incarnation->second);
      if (parsed) {
        entry.incarnation = parsed.value();
      }
    }
    return entry.control_port;
  }

  [[nodiscard]] Status kill_agent(const std::string& cluster) {
    const auto it = agents_.find(cluster);
    if (it == agents_.end()) {
      return Status::make(Outcome::NotFound, "unknown agent");
    }
    it->second.process.terminate();
    if (it->second.process.running()) {
      return Status::make(Outcome::Internal, "the agent survived a hard termination");
    }
    return Status::ok();
  }

  [[nodiscard]] std::uint16_t agent_control_port(const std::string& cluster) const {
    const auto it = agents_.find(cluster);
    return it == agents_.end() ? 0 : it->second.control_port;
  }

  [[nodiscard]] icf::IncarnationId agent_incarnation(const std::string& cluster) const {
    const auto it = agents_.find(cluster);
    return it == agents_.end() ? icf::IncarnationId{} : it->second.incarnation;
  }

  [[nodiscard]] std::string agent_log(const std::string& cluster) {
    const auto it = agents_.find(cluster);
    return it == agents_.end() ? std::string() : it->second.process.log_contents();
  }

  [[nodiscard]] std::string coordinator_log() { return coordinator_.log_contents(); }

  [[nodiscard]] Result<icf::client::Client> connect_observer(std::uint16_t port = 0,
                                                             const std::string& key = std::string()) {
    icf::client::ClientOptions options;
    options.host = "127.0.0.1";
    options.port = port == 0 ? coordinator_port_ : port;
    options.channel_key = key;
    return icf::client::Client::connect(options, *clock_);
  }

  [[nodiscard]] Result<icf::client::Client> connect_agent_control(const std::string& cluster) {
    const std::uint16_t port = agent_control_port(cluster);
    if (port == 0) {
      return Status::make(Outcome::NotFound, "unknown agent control port");
    }
    return connect_observer(port);
  }

  [[nodiscard]] Result<icf::wire::QueryResultMessage> query(icf::client::Client& client,
                                                            icf::wire::QueryMessage message) {
    message.request = icf::Uuid::random(rng_);
    return client.query(message);
  }

  [[nodiscard]] Result<icf::wire::AdminResultMessage> admin(icf::client::Client& client,
                                                            icf::wire::AdminMessage message) {
    message.request = icf::Uuid::random(rng_);
    return client.admin(message);
  }

  // Polls until the predicate reports success or the bound elapses. Returns the last status.
  template <class Predicate>
  [[nodiscard]] Status wait_until(Predicate predicate, Duration timeout, const std::string& what) {
    const std::int64_t deadline = clock_->monotonic_nanos() + timeout.nanos();
    Status last = Status::make(Outcome::Indeterminate, "the condition was never evaluated");
    while (clock_->monotonic_nanos() < deadline) {
      last = predicate();
      if (last) {
        return Status::ok();
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    last_error_ = "timed out waiting for " + what + ": " + last.to_string();
    return Status::make(Outcome::Indeterminate, last_error_);
  }

  [[nodiscard]] icf::Rng& rng() noexcept { return rng_; }

  // Adds the policy rules, link, and path a pair needs, using the coordinator's administrative
  // protocol exactly as an operator would.
  [[nodiscard]] Status bootstrap_pair(const std::string& cluster_a, const std::string& cluster_b,
                                      const std::string& endpoint_a, const std::string& endpoint_b,
                                      const std::string& domain_a = "domain-north",
                                      const std::string& domain_b = "domain-south") {
    Result<icf::client::Client> client = connect_observer();
    if (!client) {
      return set_error(client.status());
    }
    for (const std::string& domain : {domain_a, domain_b}) {
      icf::wire::AdminMessage rule;
      rule.action = icf::wire::AdminAction::UpsertPolicy;
      icf::model::PolicyRule policy;
      policy.id = "allow-" + cluster_a + "-" + cluster_b + "-" + domain;
      policy.owner = icf::AuthorityDomainId::parse(domain).value();
      policy.cluster_a = icf::ClusterId::parse(cluster_a).value();
      policy.cluster_b = icf::ClusterId::parse(cluster_b).value();
      policy.generation = icf::PolicyGeneration(1);
      policy.allow = true;
      policy.allow_degraded = true;
      policy.provenance.source = icf::model::EvidenceSource::AdminConfigured;
      policy.provenance.verification = icf::model::VerificationState::Verified;
      rule.policy = policy;
      Result<icf::wire::AdminResultMessage> applied = admin(client.value(), rule);
      if (!applied || applied.value().outcome != icf::Outcome::Ok) {
        return set_error(applied ? icf::Status::make(applied.value().outcome, applied.value().detail)
                                 : applied.status());
      }
    }
    {
      icf::wire::AdminMessage link;
      link.action = icf::wire::AdminAction::UpsertLink;
      icf::model::LinkRecord record;
      record.id = icf::EdgeId::parse(cluster_a + "-" + cluster_b).value();
      record.a = icf::EndpointId::parse(endpoint_a).value();
      record.b = icf::EndpointId::parse(endpoint_b).value();
      record.kind = icf::model::LinkKind::LoopbackTcp;
      record.state = icf::model::LinkState::Up;
      record.capacity = icf::CapacityUnits(1000);
      record.provenance.source = icf::model::EvidenceSource::AdminConfigured;
      record.provenance.verification = icf::model::VerificationState::Verified;
      link.link = record;
      Result<icf::wire::AdminResultMessage> applied = admin(client.value(), link);
      if (!applied || applied.value().outcome != icf::Outcome::Ok) {
        return set_error(applied ? icf::Status::make(applied.value().outcome, applied.value().detail)
                                 : applied.status());
      }
    }
    {
      icf::wire::AdminMessage path;
      path.action = icf::wire::AdminAction::UpsertPath;
      icf::model::PathRecord record;
      record.id = icf::PathId::parse(cluster_a + "-" + cluster_b).value();
      record.a = icf::EndpointId::parse(endpoint_a).value();
      record.b = icf::EndpointId::parse(endpoint_b).value();
      record.hops.push_back(icf::EdgeId::parse(cluster_a + "-" + cluster_b).value());
      record.provenance.source = icf::model::EvidenceSource::DerivedFromTopology;
      record.provenance.verification = icf::model::VerificationState::Verified;
      path.path = record;
      Result<icf::wire::AdminResultMessage> applied = admin(client.value(), path);
      if (!applied || applied.value().outcome != icf::Outcome::Ok) {
        return set_error(applied ? icf::Status::make(applied.value().outcome, applied.value().detail)
                                 : applied.status());
      }
    }
    return Status::ok();
  }

  // Proposes a contract and issues a grant; the agents run their own consent and commit steps.
  [[nodiscard]] Status establish_grant(const std::string& cluster_a, const std::string& cluster_b,
                                       const std::string& endpoint_a, const std::string& endpoint_b,
                                       icf::CapacityUnits capacity = icf::CapacityUnits(50)) {
    Result<icf::client::Client> client = connect_observer();
    if (!client) {
      return set_error(client.status());
    }
    icf::wire::AdminMessage propose;
    propose.action = icf::wire::AdminAction::AuthorizeContract;
    propose.cluster_id = icf::ClusterId::parse(cluster_a).value();
    propose.cluster_b = icf::ClusterId::parse(cluster_b).value();
    propose.endpoint = icf::EndpointId::parse(endpoint_a).value();
    propose.endpoint_b = icf::EndpointId::parse(endpoint_b).value();
    propose.capacity = capacity;
    propose.lease_duration = icf::Duration::from_seconds(120);
    Result<icf::wire::AdminResultMessage> proposed = admin(client.value(), propose);
    if (!proposed || proposed.value().outcome != icf::Outcome::Ok) {
      return set_error(proposed ? icf::Status::make(proposed.value().outcome,
                                                    std::string("proposing the contract returned ") +
                                                        ::icf::to_string(proposed.value().outcome) + ": " +
                                                        proposed.value().detail)
                                : proposed.status());
    }
    // The coordinator reports the identity of the contract it created; picking "the last one in
    // the map" would silently address an older contract for the same pair.
    const icf::ContractId contract = proposed.value().contract;
    if (contract.is_nil()) {
      return set_error(icf::Status::make(icf::Outcome::Invalid,
                                         "the coordinator accepted the proposal but reported no contract identity"));
    }
    // The agents consent asynchronously over their own connections, so wait until both sides
    // have accepted the identical terms before issuing a grant, exactly as an operator would.
    const icf::Status consented = wait_until(
        [&]() -> icf::Status {
          icf::wire::QueryMessage query;
          query.kind = icf::wire::QueryKind::ShowContract;
          query.contract = contract;
          icf::Result<icf::client::Client> observer = connect_observer();
          if (!observer) {
            return observer.status();
          }
          icf::Result<icf::wire::QueryResultMessage> result = this->query(observer.value(), query);
          if (!result) {
            return result.status();
          }
          if (result.value().contracts.empty()) {
            return icf::Status::make(icf::Outcome::NotFound, "the contract is not visible");
          }
          const icf::model::ContractState state = result.value().contracts.front().state;
          if (state == icf::model::ContractState::Consented || state == icf::model::ContractState::Active) {
            return icf::Status::ok();
          }
          return icf::Status::make(icf::Outcome::Incomplete,
                                   std::string("the contract is in state ") + icf::model::to_string(state));
        },
        icf::Duration::from_seconds(20), "both cluster agents to consent");
    if (!consented) {
      return set_error(consented);
    }
    icf::wire::AdminMessage issue;
    issue.action = icf::wire::AdminAction::IssueGrant;
    issue.contract = contract;
    issue.capacity = capacity;
    Result<icf::wire::AdminResultMessage> issued = admin(client.value(), issue);
    if (!issued || issued.value().outcome != icf::Outcome::Ok) {
      return set_error(issued ? icf::Status::make(issued.value().outcome,
                                                  std::string("issuing the grant returned ") +
                                                      ::icf::to_string(issued.value().outcome) + ": " +
                                                      issued.value().detail)
                              : issued.status());
    }
    return Status::ok();
  }

  // Asks the coordinator for a decision over the pair.
  [[nodiscard]] Result<icf::model::Decision> decide(const std::string& endpoint_a, const std::string& endpoint_b,
                                                    icf::CapacityUnits capacity = icf::CapacityUnits(10)) {
    Result<icf::client::Client> client = connect_observer();
    if (!client) {
      return client.status();
    }
    icf::wire::QueryMessage query;
    query.kind = icf::wire::QueryKind::Decide;
    query.endpoint = icf::EndpointId::parse(endpoint_a).value();
    query.endpoint_b = icf::EndpointId::parse(endpoint_b).value();
    query.capacity = capacity;
    query.request = icf::Uuid::random(rng_);
    Result<icf::wire::QueryResultMessage> result = client.value().query(query);
    if (!result) {
      return result.status();
    }
    if (!result.value().decision.has_value()) {
      return icf::Status::make(result.value().outcome, result.value().detail);
    }
    return result.value().decision.value();
  }

  // Waits until the coordinator reports the expected number of connected agent sessions. A
  // recovered cluster record is not a live connection, so this is the signal a restart test needs.
  [[nodiscard]] std::size_t connected_agents() {
    icf::Result<icf::client::Client> client = connect_observer();
    if (!client) {
      return 0;
    }
    icf::wire::QueryMessage query;
    query.kind = icf::wire::QueryKind::Status;
    query.request = icf::Uuid::random(rng_);
    icf::Result<icf::wire::QueryResultMessage> result = client.value().query(query);
    if (!result || !result.value().status.has_value()) {
      return 0;
    }
    return result.value().status->connected_agents;
  }

  [[nodiscard]] Status wait_for_connected_agents(std::size_t expected, Duration timeout) {
    return wait_until(
        [this, expected]() -> Status {
          icf::Result<icf::client::Client> client = connect_observer();
          if (!client) {
            return client.status();
          }
          icf::wire::QueryMessage query;
          query.kind = icf::wire::QueryKind::Status;
          query.request = icf::Uuid::random(rng_);
          icf::Result<icf::wire::QueryResultMessage> result = client.value().query(query);
          if (!result || !result.value().status.has_value()) {
            return icf::Status::make(icf::Outcome::Incomplete, "the coordinator returned no status");
          }
          if (result.value().status->connected_agents < expected) {
            return icf::Status::make(icf::Outcome::Incomplete,
                                     std::to_string(result.value().status->connected_agents) +
                                         " agent session(s) connected");
          }
          return icf::Status::ok();
        },
        timeout, std::to_string(expected) + " agent session(s) to connect");
  }

  // Waits until both agents have registered their endpoint scopes with the coordinator.
  [[nodiscard]] Status wait_for_registration(const std::string& cluster, Duration timeout) {
    return wait_until(
        [this, &cluster]() -> Status {
          Result<icf::client::Client> client = connect_observer();
          if (!client) {
            return client.status();
          }
          icf::wire::QueryMessage query;
          query.kind = icf::wire::QueryKind::ShowCluster;
          query.cluster = icf::ClusterId::parse(cluster).value();
          query.request = icf::Uuid::random(rng_);
          Result<icf::wire::QueryResultMessage> result = client.value().query(query);
          if (!result) {
            return result.status();
          }
          if (result.value().clusters.empty()) {
            return icf::Status::make(icf::Outcome::NotFound, "the cluster has not reported yet");
          }
          if (result.value().clusters.front().endpoints.empty()) {
            return icf::Status::make(icf::Outcome::Incomplete, "the cluster has reported no endpoint scopes");
          }
          return icf::Status::ok();
        },
        timeout, "cluster " + cluster + " to register");
  }

 private:
  Status set_error(const Status& status) {
    last_error_ = status.to_string();
    return status;
  }

  struct AgentEntry {
    ChildProcess process;
    std::uint16_t control_port = 0;
    std::uint64_t generation = 0;
    icf::IncarnationId incarnation;
  };

  std::unique_ptr<TempDir> directory_;
  std::string bin_dir_;
  std::unique_ptr<icf::SystemClock> clock_;
  ChildProcess coordinator_;
  std::uint16_t coordinator_port_ = 0;
  icf::Term coordinator_term_{};
  std::map<std::string, AgentEntry> agents_;
  icf::Rng rng_{icf::entropy_seed()};
  std::string last_error_;
};

}  // namespace icf::test
