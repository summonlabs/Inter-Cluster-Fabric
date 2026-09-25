// icfd - the Inter-Cluster Fabric coordinator daemon.
//
// Owns authoritative cluster identities, generations, endpoint scopes, links, policy, two-sided
// contracts, grants, and the authority term. Durable state lives in the state directory; the
// process is safe to kill at any point because every authorization is written before it is
// reported.
#include <cstdio>
#include <memory>
#include <string>

#include "app_support.hpp"
#include "icf/core/log.hpp"
#include "icf/runtime/coordinator.hpp"

namespace {

const std::vector<std::string_view> kKnownKeys{
    "state_dir",   "listen_address", "listen_port", "domain",   "durable", "allow_agent_registration",
    "agent_idle_ms", "lease_ms",     "ping_ms",     "compact_bytes", "ready_file", "log_level",
};

void print_usage() {
  std::fprintf(stderr,
               "usage: icfd --state-dir <dir> [options]\n"
               "  --config <file>            configuration file (key = value)\n"
               "  --state-dir <dir>          durable state directory (required)\n"
               "  --domain <id>              authority domain identity (required)\n"
               "  --listen <host:port>       listen address (default 127.0.0.1:0)\n"
               "  --ready-file <path>        file written once the listener is bound\n"
               "  --durable <bool>           fsync every durable write (default true)\n"
               "  --allow-agent-registration <bool>  accept unregistered cluster identities (default true)\n"
               "  --log-level <level>        trace|debug|info|warn|error|off\n"
               "  --domain-key.<domain> <k>  shared channel key for one authority domain\n");
}

}  // namespace

int main(int argc, char** argv) {
  icf::app::install_signal_handlers();
  icf::Result<icf::app::Arguments> arguments = icf::app::parse_arguments(argc, argv);
  if (!arguments) {
    std::fprintf(stderr, "icfd: %s\n", arguments.status().message().c_str());
    return 2;
  }
  if (arguments.value().has("help")) {
    print_usage();
    return 0;
  }
  icf::Result<icf::Config> config = icf::app::load_config(arguments.value());
  if (!config) {
    std::fprintf(stderr, "icfd: %s\n", config.status().message().c_str());
    return 2;
  }
  icf::Logger::instance().set_level(icf::app::log_level_from(arguments.value(), icf::LogLevel::Info));

  const std::string state_dir = icf::app::config_string(config.value(), arguments.value(), "state_dir", "");
  const std::string domain_text = icf::app::config_string(config.value(), arguments.value(), "domain", "");
  if (state_dir.empty() || domain_text.empty()) {
    print_usage();
    std::fprintf(stderr, "icfd: --state-dir and --domain are required\n");
    return 2;
  }

  const std::string listen = icf::app::config_string(config.value(), arguments.value(), "listen",
                                                     icf::app::config_string(config.value(), arguments.value(),
                                                                             "listen_address", "127.0.0.1") +
                                                         ":" +
                                                         std::to_string(icf::app::config_u64(
                                                             config.value(), arguments.value(), "listen_port", 0)));
  icf::Result<std::pair<std::string, std::uint16_t>> endpoint = icf::app::parse_endpoint(listen);
  if (!endpoint) {
    std::fprintf(stderr, "icfd: %s\n", endpoint.status().message().c_str());
    return 2;
  }

  icf::runtime::Coordinator::Config coordinator_config;
  coordinator_config.state_directory = state_dir;
  coordinator_config.listen_address = endpoint.value().first;
  coordinator_config.listen_port = endpoint.value().second;
  coordinator_config.durable = icf::app::config_bool(config.value(), arguments.value(), "durable", true);
  coordinator_config.allow_agent_registration =
      icf::app::config_bool(config.value(), arguments.value(), "allow_agent_registration", true);
  coordinator_config.domain_keys = icf::app::channel_keys(config.value());
  coordinator_config.agent_idle_deadline = icf::Duration::from_millis(
      icf::app::config_u64(config.value(), arguments.value(), "agent_idle_ms", 30000));
  coordinator_config.default_lease = icf::Duration::from_millis(
      icf::app::config_u64(config.value(), arguments.value(), "lease_ms", 120000));
  coordinator_config.ping_interval = icf::Duration::from_millis(
      icf::app::config_u64(config.value(), arguments.value(), "ping_ms", 5000));
  coordinator_config.compact_bytes =
      icf::app::config_u64(config.value(), arguments.value(), "compact_bytes", 8ull << 20);
  coordinator_config.readiness_file = icf::app::config_string(config.value(), arguments.value(), "ready_file", "");

  icf::Result<icf::AuthorityDomainId> domain = icf::AuthorityDomainId::parse(domain_text);
  if (!domain) {
    std::fprintf(stderr, "icfd: %s\n", domain.status().message().c_str());
    return 2;
  }
  coordinator_config.domain = domain.value();

  icf::SystemClock clock;
  icf::Result<std::unique_ptr<icf::runtime::Coordinator>> coordinator =
      icf::runtime::Coordinator::create(std::move(coordinator_config), clock);
  if (!coordinator) {
    std::fprintf(stderr, "icfd: %s\n", coordinator.status().to_string().c_str());
    return 1;
  }
  const icf::runtime::Coordinator& running = *coordinator.value();
  ICF_LOG_INFO_KF("icfd", "coordinator ready",
                  (std::initializer_list<std::pair<std::string_view, std::string_view>>{
                      {"domain", domain.value().c_str()},
                      {"port", std::to_string(running.port()).c_str()},
                      {"term", std::to_string(running.term().value()).c_str()}}));
  std::fprintf(stdout, "icfd: listening on %s:%u term=%llu recovered=%s\n", endpoint.value().first.c_str(),
               static_cast<unsigned>(running.port()), static_cast<unsigned long long>(running.term().value()),
               running.recovery().recovered_from_store ? "true" : "false");
  std::fflush(stdout);

  const icf::Status served = coordinator.value()->serve();
  coordinator.value()->stop();
  if (!served) {
    std::fprintf(stderr, "icfd: %s\n", served.to_string().c_str());
    return 1;
  }
  std::fprintf(stdout, "icfd: stopped\n");
  return 0;
}
