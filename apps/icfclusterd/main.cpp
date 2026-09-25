// icfclusterd - the cluster-side agent daemon.
//
// Owns one cluster identity: its incarnation, generation, policy generation, endpoint scopes,
// local consents, and the enforcement records it durably installs. It exposes a local control
// channel for inspection and cluster-local administration.
#include <cstdio>
#include <memory>
#include <string>

#include "app_support.hpp"
#include "icf/core/log.hpp"
#include "icf/runtime/agent.hpp"

namespace {

void print_usage() {
  std::fprintf(stderr,
               "usage: icfclusterd --cluster <id> --domain <id> --coordinator <host:port> [options]\n"
               "  --config <file>            configuration file (key = value)\n"
               "  --cluster <id>             cluster identity (required)\n"
               "  --domain <id>              authority domain identity (required)\n"
               "  --coordinator <host:port>  coordinator address (required)\n"
               "  --generation <n>           cluster generation (default 1)\n"
               "  --policy-generation <n>    policy generation (default 1)\n"
               "  --state-dir <dir>          durable state directory (required)\n"
               "  --control <host:port>      local control address (default 127.0.0.1:0)\n"
               "  --ready-file <path>        file written once the control listener is bound\n"
               "  --shared-key <key>         shared channel key for the domain\n"
               "  --state <active|suspended|draining>  initial cluster state\n"
               "  --log-level <level>        trace|debug|info|warn|error|off\n"
               "  endpoint.<id>.scope|capacity|degraded|allow   endpoint declarations\n");
}

}  // namespace

int main(int argc, char** argv) {
  icf::app::install_signal_handlers();
  icf::Result<icf::app::Arguments> arguments = icf::app::parse_arguments(argc, argv);
  if (!arguments) {
    std::fprintf(stderr, "icfclusterd: %s\n", arguments.status().message().c_str());
    return 2;
  }
  if (arguments.value().has("help")) {
    print_usage();
    return 0;
  }
  icf::Result<icf::Config> config = icf::app::load_config(arguments.value());
  if (!config) {
    std::fprintf(stderr, "icfclusterd: %s\n", config.status().message().c_str());
    return 2;
  }
  icf::Logger::instance().set_level(icf::app::log_level_from(arguments.value(), icf::LogLevel::Info));

  const std::string cluster_text = icf::app::config_string(config.value(), arguments.value(), "cluster", "");
  const std::string domain_text = icf::app::config_string(config.value(), arguments.value(), "domain", "");
  const std::string coordinator_text = icf::app::config_string(config.value(), arguments.value(), "coordinator", "");
  const std::string state_dir = icf::app::config_string(config.value(), arguments.value(), "state_dir", "");
  if (cluster_text.empty() || domain_text.empty() || coordinator_text.empty() || state_dir.empty()) {
    print_usage();
    std::fprintf(stderr, "icfclusterd: --cluster, --domain, --coordinator, and --state-dir are required\n");
    return 2;
  }

  icf::Result<icf::AuthorityDomainId> domain = icf::AuthorityDomainId::parse(domain_text);
  if (!domain) {
    std::fprintf(stderr, "icfclusterd: %s\n", domain.status().message().c_str());
    return 2;
  }
  icf::Result<std::pair<std::string, std::uint16_t>> coordinator_address = icf::app::parse_endpoint(coordinator_text);
  if (!coordinator_address) {
    std::fprintf(stderr, "icfclusterd: %s\n", coordinator_address.status().message().c_str());
    return 2;
  }

  icf::runtime::Agent::Config agent_config;
  icf::Result<icf::ClusterId> cluster = icf::ClusterId::parse(cluster_text);
  if (!cluster) {
    std::fprintf(stderr, "icfclusterd: %s\n", cluster.status().message().c_str());
    return 2;
  }
  agent_config.cluster = cluster.value();
  agent_config.domain = domain.value();
  agent_config.generation = icf::Generation(
      icf::app::config_u64(config.value(), arguments.value(), "generation", 1));
  agent_config.policy_generation = icf::PolicyGeneration(
      icf::app::config_u64(config.value(), arguments.value(), "policy_generation", 1));
  agent_config.coordinator_host = coordinator_address.value().first;
  agent_config.coordinator_port = coordinator_address.value().second;
  agent_config.state_directory = state_dir;
  agent_config.channel_key = icf::app::config_string(config.value(), arguments.value(), "shared_key", "");
  agent_config.durable = icf::app::config_bool(config.value(), arguments.value(), "durable", true);
  agent_config.readiness_file = icf::app::config_string(config.value(), arguments.value(), "ready_file", "");

  const std::string control = icf::app::config_string(config.value(), arguments.value(), "control", "127.0.0.1:0");
  icf::Result<std::pair<std::string, std::uint16_t>> control_address = icf::app::parse_endpoint(control);
  if (!control_address) {
    std::fprintf(stderr, "icfclusterd: %s\n", control_address.status().message().c_str());
    return 2;
  }
  agent_config.control_address = control_address.value().first;
  agent_config.control_port = control_address.value().second;

  const std::string state_text = icf::app::config_string(config.value(), arguments.value(), "state", "active");
  if (state_text == "active") {
    agent_config.state = icf::model::ClusterState::Active;
  } else if (state_text == "suspended") {
    agent_config.state = icf::model::ClusterState::Suspended;
  } else if (state_text == "draining") {
    agent_config.state = icf::model::ClusterState::Draining;
  } else {
    std::fprintf(stderr, "icfclusterd: --state must be active, suspended, or draining\n");
    return 2;
  }

  icf::Result<std::vector<icf::model::EndpointRecord>> endpoints = icf::app::parse_endpoints(config.value(), cluster.value());
  if (!endpoints) {
    std::fprintf(stderr, "icfclusterd: %s\n", endpoints.status().message().c_str());
    return 2;
  }
  agent_config.endpoints = endpoints.value();

  icf::SystemClock clock;
  icf::Result<std::unique_ptr<icf::runtime::Agent>> agent = icf::runtime::Agent::create(std::move(agent_config), clock);
  if (!agent) {
    std::fprintf(stderr, "icfclusterd: %s\n", agent.status().to_string().c_str());
    return 1;
  }
  std::fprintf(stdout, "icfclusterd: cluster=%s control_port=%u incarnation=%s term=%llu generation=%llu\n",
               cluster.value().c_str(), static_cast<unsigned>(agent.value()->control_port()),
               agent.value()->incarnation().to_string().c_str(),
               static_cast<unsigned long long>(agent.value()->local_term().value()),
               static_cast<unsigned long long>(agent.value()->generation().value()));
  std::fflush(stdout);

  const icf::Status served = agent.value()->serve();
  agent.value()->stop();
  if (!served) {
    std::fprintf(stderr, "icfclusterd: %s\n", served.to_string().c_str());
    return 1;
  }
  std::fprintf(stdout, "icfclusterd: stopped\n");
  return 0;
}
