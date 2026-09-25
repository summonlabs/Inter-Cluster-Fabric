// icfctl - inspection and administration client for the Inter-Cluster Fabric.
//
// Every command maps onto the same protocol the daemons speak, so the CLI can never do
// something the runtime would refuse to an ordinary operator session. Exit codes are stable:
//   0  the operation completed with outcome OK
//   2  the transport failed (the peer could not be reached or the session was refused)
//   3  connectivity is authorized, but only over a degraded path
//   4  the operation returned a typed negative outcome (the outcome name is printed)
//   1  usage or local failure
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "app_support.hpp"
#include "icf/client/client.hpp"
#include "icf/core/log.hpp"
#include "icf/core/rng.hpp"
#include "icf/version.hpp"

namespace {

using icf::Outcome;
using icf::Status;

struct Context {
  icf::app::Arguments arguments;
  icf::Rng rng{icf::entropy_seed()};
};

[[nodiscard]] icf::Uuid new_request(Context& context) { return icf::Uuid::random(context.rng); }

void print_outcome(const Status& status) {
  std::printf("outcome=%s\n", icf::to_string(status.outcome()));
  if (!status.message().empty()) {
    std::printf("detail=%s\n", status.message().c_str());
  }
}

int exit_code_for(Outcome outcome) {
  if (outcome == Outcome::Ok) {
    return 0;
  }
  if (outcome == Outcome::DegradedAuthorized) {
    return 3;
  }
  if (icf::is_indeterminate_family(outcome)) {
    return 4;
  }
  return 4;
}

[[nodiscard]] std::string join(const std::vector<std::string>& values, char separator) {
  std::string out;
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index > 0) {
      out.push_back(separator);
    }
    out += values[index];
  }
  return out;
}

void print_cluster(const icf::model::ClusterRecord& cluster) {
  std::printf("cluster=%s domain=%s state=%s generation=%llu policy_generation=%llu incarnation=%s\n",
              cluster.id.c_str(), cluster.domain.c_str(), icf::model::to_string(cluster.state),
              static_cast<unsigned long long>(cluster.generation.value()),
              static_cast<unsigned long long>(cluster.policy_generation.value()),
              cluster.incarnation.to_string().c_str());
  std::printf("  endpoints=%zu incarnation_changes=%llu generation_conflict=%s consent_withdrawn=%s\n",
              cluster.endpoints.size(), static_cast<unsigned long long>(cluster.incarnation_changes),
              cluster.generation_conflict ? "true" : "false", cluster.consent_withdrawn ? "true" : "false");
  for (const icf::model::EndpointRecord& endpoint : cluster.endpoints) {
    std::printf("  endpoint=%s scope=%s state=%s capacity=%llu reserved=%llu inter_cluster=%s degraded=%s\n",
                endpoint.id.c_str(), endpoint.scope.c_str(), icf::model::to_string(endpoint.state),
                static_cast<unsigned long long>(endpoint.capacity.value()),
                static_cast<unsigned long long>(endpoint.reserved.value()),
                endpoint.inter_cluster_allowed ? "allowed" : "refused",
                endpoint.permits_degraded ? "permitted" : "not-permitted");
  }
}

void print_link(const icf::model::LinkRecord& link) {
  std::printf("link=%s a=%s b=%s kind=%s state=%s capacity=%llu provenance=%s/%s\n", link.id.c_str(),
              link.a.c_str(), link.b.c_str(), icf::model::to_string(link.kind),
              icf::model::to_string(link.state), static_cast<unsigned long long>(link.capacity.value()),
              icf::model::to_string(link.provenance.source),
              icf::model::to_string(link.provenance.verification));
}

void print_path(const icf::model::PathRecord& path) {
  std::vector<std::string> hops;
  hops.reserve(path.hops.size());
  for (const icf::EdgeId& hop : path.hops) {
    hops.push_back(hop.str());
  }
  std::printf("path=%s a=%s b=%s state=%s bottleneck=%llu hops=%s unsupported_edge=%s\n", path.id.c_str(),
              path.a.c_str(), path.b.c_str(), icf::model::to_string(path.state),
              static_cast<unsigned long long>(path.bottleneck.value()), join(hops, ',').c_str(),
              path.contains_unsupported_edge ? "true" : "false");
}

void print_policy(const icf::model::PolicyRule& rule) {
  std::printf("policy=%s owner=%s effect=%s a=%s b=%s endpoint_a=%s endpoint_b=%s generation=%llu degraded=%s\n",
              rule.id.c_str(), rule.owner.c_str(), rule.allow ? "allow" : "refuse",
              rule.cluster_a.empty() ? "*" : rule.cluster_a.c_str(), rule.cluster_b.empty() ? "*" : rule.cluster_b.c_str(),
              rule.endpoint_a.empty() ? "*" : rule.endpoint_a.c_str(),
              rule.endpoint_b.empty() ? "*" : rule.endpoint_b.c_str(),
              static_cast<unsigned long long>(rule.generation.value()),
              rule.allow_degraded ? "permitted" : "not-permitted");
}

void print_contract(const icf::model::ContractRecord& contract) {
  std::printf("contract=%s state=%s capacity=%llu lease_ms=%lld\n", contract.id.to_string().c_str(),
              icf::model::to_string(contract.state),
              static_cast<unsigned long long>(contract.capacity.value()),
              static_cast<long long>(contract.lease_duration.millis()));
  std::printf("  terms_digest=%s\n", contract.terms_digest.hex().c_str());
  for (std::size_t side = 0; side < contract.parties.size(); ++side) {
    const icf::model::PartyRef& party = contract.parties[side];
    std::printf("  party%zu cluster=%s endpoint=%s domain=%s\n", side, party.cluster.c_str(),
                party.endpoint.c_str(), party.domain.c_str());
    if (contract.consents[side].has_value()) {
      const icf::model::ConsentRecord& consent = *contract.consents[side];
      std::printf("    consent=%s generation=%llu policy_generation=%llu incarnation=%s authenticity=%s\n",
                  icf::model::to_string(consent.decision),
                  static_cast<unsigned long long>(consent.generation.value()),
                  static_cast<unsigned long long>(consent.policy_generation.value()),
                  consent.incarnation.to_string().c_str(), icf::model::to_string(consent.authenticity));
    } else {
      std::printf("    consent=absent\n");
    }
  }
}

void print_grant(const icf::model::GrantRecord& grant) {
  std::printf("grant=%s contract=%s state=%s attempt=%s capacity=%llu\n", grant.id.to_string().c_str(),
              grant.contract.to_string().c_str(), icf::model::to_string(grant.state),
              grant.attempt.to_string().c_str(), static_cast<unsigned long long>(grant.capacity.value()));
  std::printf("  coordinator_term=%llu coordinator=%s valid_until=%s\n",
              static_cast<unsigned long long>(grant.coordinator_term.value()),
              grant.coordinator.to_string().c_str(), grant.valid_until.to_iso8601().c_str());
  std::printf("  acknowledged_a=%s acknowledged_b=%s note=%s\n", grant.acknowledged[0] ? "true" : "false",
              grant.acknowledged[1] ? "true" : "false", grant.note.c_str());
}

void print_decision(const icf::model::Decision& decision) {
  std::vector<std::string> reasons;
  reasons.reserve(decision.reasons.size());
  for (const icf::model::ReasonCode code : decision.reasons) {
    reasons.push_back(icf::model::to_string(code));
  }
  std::vector<std::string> paths;
  for (const icf::PathId& path : decision.paths) {
    paths.push_back(path.str());
  }
  std::printf("outcome=%s\n", icf::to_string(decision.outcome));
  std::printf("detail=%s\n", decision.detail.c_str());
  std::printf("degraded=%s\n", decision.degraded ? "true" : "false");
  std::printf("contract=%s\n", decision.contract.is_nil() ? "-" : decision.contract.to_string().c_str());
  std::printf("grant=%s\n", decision.grant.is_nil() ? "-" : decision.grant.to_string().c_str());
  std::printf("authorities=%s,%s\n", decision.authorities[0].empty() ? "-" : decision.authorities[0].c_str(),
              decision.authorities[1].empty() ? "-" : decision.authorities[1].c_str());
  const std::string path_text = paths.empty() ? std::string("-") : join(paths, ',');
  std::printf("paths=%s\n", path_text.c_str());
  const std::string reason_text = reasons.empty() ? std::string("-") : join(reasons, ',');
  std::printf("reasons=%s\n", reason_text.c_str());
  std::printf("view_digest=%s\n", decision.view_digest.hex().c_str());
  std::printf("term=%llu\n", static_cast<unsigned long long>(decision.term.value()));
}

void print_fence_plan(const icf::model::FencePlan& plan) {
  std::printf("trigger=%s\n", icf::model::to_string(plan.trigger));
  std::printf("actions=%zu\n", plan.actions.size());
  for (const icf::model::FenceAction& action : plan.actions) {
    std::printf("  action=%s grant=%s contract=%s reservation=%s reason=%s\n",
                icf::model::to_string(action.target),
                action.grant.is_nil() ? "-" : action.grant.to_string().c_str(),
                action.contract.is_nil() ? "-" : action.contract.to_string().c_str(),
                action.reservation.is_nil() ? "-" : action.reservation.to_string().c_str(),
                icf::model::to_string(action.reason));
  }
}

void print_status(const icf::model::CoordinatorStatus& status, const char* role) {
  std::printf("role=%s\n", role);
  std::printf("domain=%s\n", status.domain.c_str());
  std::printf("incarnation=%s\n", status.incarnation.to_string().c_str());
  std::printf("term=%llu\n", static_cast<unsigned long long>(status.term.value()));
  std::printf("started_at=%s\n", status.started_at.to_iso8601().c_str());
  std::printf("view_digest=%s\n", status.view_digest.hex().c_str());
  std::printf("recovered_from_store=%s recovered_records=%llu truncations=%llu\n",
              status.recovered_from_store ? "true" : "false",
              static_cast<unsigned long long>(status.recovered_records),
              static_cast<unsigned long long>(status.truncations_recovered));
  std::printf("clusters=%zu endpoints=%zu links=%zu paths=%zu contracts=%zu grants=%zu reservations=%zu policies=%zu\n",
              status.clusters, status.endpoints, status.links, status.paths, status.contracts, status.grants,
              status.reservations, status.policies);
  std::printf("commits=%llu fences=%llu refusals=%llu revalidations=%llu rejected_replays=%llu rejected_frames=%llu\n",
              static_cast<unsigned long long>(status.commits), static_cast<unsigned long long>(status.fences),
              static_cast<unsigned long long>(status.refusals),
              static_cast<unsigned long long>(status.revalidations),
              static_cast<unsigned long long>(status.rejected_replays),
              static_cast<unsigned long long>(status.rejected_frames));
  std::printf("connected_agents=%zu\n", status.connected_agents);
  std::printf("store=%s\n", status.store_path.c_str());
}

[[nodiscard]] icf::Result<icf::client::Client> connect_client(const std::string& address, const std::string& key) {
  icf::Result<std::pair<std::string, std::uint16_t>> endpoint = icf::app::parse_endpoint(address);
  if (!endpoint) {
    return endpoint.status();
  }
  icf::client::ClientOptions options;
  options.host = endpoint.value().first;
  options.port = endpoint.value().second;
  options.role = icf::wire::PeerRole::Observer;
  options.channel_key = key;
  static icf::SystemClock clock;
  return icf::client::Client::connect(options, clock);
}

[[nodiscard]] icf::model::Provenance admin_provenance() {
  icf::model::Provenance provenance;
  provenance.source = icf::model::EvidenceSource::AdminConfigured;
  provenance.verification = icf::model::VerificationState::Verified;
  return provenance;
}

int run_query(Context& context, const std::string& address, const std::string& key, icf::wire::QueryMessage query,
              const std::function<void(const icf::wire::QueryResultMessage&)>& print) {
  icf::Result<icf::client::Client> client = connect_client(address, key);
  if (!client) {
    std::printf("outcome=%s\ndetail=%s\n", icf::to_string(client.status().outcome()),
                client.status().message().c_str());
    return 2;
  }
  query.request = new_request(context);
  icf::Result<icf::wire::QueryResultMessage> result = client.value().query(query);
  if (!result) {
    std::printf("outcome=%s\ndetail=%s\n", icf::to_string(result.status().outcome()),
                result.status().message().c_str());
    return 2;
  }
  if (result.value().outcome != Outcome::Ok && !result.value().decision.has_value()) {
    std::printf("outcome=%s\ndetail=%s\n", icf::to_string(result.value().outcome),
                result.value().detail.c_str());
    return exit_code_for(result.value().outcome);
  }
  print(result.value());
  return result.value().decision.has_value() ? exit_code_for(result.value().decision->outcome) : 0;
}

int run_admin(Context& context, const std::string& address, const std::string& key, icf::wire::AdminMessage message) {
  icf::Result<icf::client::Client> client = connect_client(address, key);
  if (!client) {
    std::printf("outcome=%s\ndetail=%s\n", icf::to_string(client.status().outcome()),
                client.status().message().c_str());
    return 2;
  }
  message.request = new_request(context);
  icf::Result<icf::wire::AdminResultMessage> result = client.value().admin(message);
  if (!result) {
    std::printf("outcome=%s\ndetail=%s\n", icf::to_string(result.status().outcome()),
                result.status().message().c_str());
    return 2;
  }
  std::printf("outcome=%s\n", icf::to_string(result.value().outcome));
  std::printf("detail=%s\n", result.value().detail.c_str());
  std::printf("view_digest=%s\n", result.value().view_digest.hex().c_str());
  return exit_code_for(result.value().outcome);
}

void print_usage() {
  std::fprintf(stderr,
               "usage: icfctl --connect <host:port> [--shared-key <key>] <command> [options]\n"
               "commands:\n"
               "  status\n"
               "  clusters [list|show <cluster>]\n"
               "  links [list|add <edge> --a <endpoint> --b <endpoint> [--kind loopback|synthetic|optical]"
               " [--capacity N]|fail <edge>|restore <edge>|degrade <edge>]\n"
               "  paths [list|add <path> --a <endpoint> --b <endpoint> --hops <e1,e2>|delete <path>]\n"
               "  policies [list|allow <rule> --owner <domain> [--a <cluster>] [--b <cluster>] [--degraded]"
               " [--max-capacity N]|refuse <rule> --owner <domain> [--a <cluster>] [--b <cluster>]|delete <rule>]\n"
               "  contracts [list|show <contract>]\n"
               "  propose --a <cluster> --endpoint <endpoint> --b <cluster> --endpoint-b <endpoint>"
               " [--capacity N] [--lease 60s]\n"
               "  grants [list|show <grant>]\n"
               "  grant --contract <contract> [--capacity N]\n"
               "  revalidate --grant <grant>\n"
               "  fence --grant <grant>\n"
               "  decide --src <endpoint> --dst <endpoint> [--capacity N] [--allow-degraded]"
               " [--expect-src-generation N] [--expect-dst-generation N]\n"
               "  fence-plan --cluster <cluster> [--trigger manual|reincarnation|withdrawal|policy|coordinator]\n"
               "  withdraw --cluster <cluster> [--reason <text>]\n"
               "  resolve --cluster <cluster> --generation N\n"
               "  accounting [--limit N]\n"
               "  audit [--limit N]\n"
               "  agent-status --agent <host:port>\n"
               "  agent-grants --agent <host:port>\n"
               "  agent-show --agent <host:port> --grant <grant>\n"
               "  agent-withdraw --agent <host:port> [--reason <text>]\n"
               "  agent-state --agent <host:port> --state active|suspended|draining\n"
               "  agent-bump --agent <host:port> [--reason <text>]\n"
               "  agent-fence --agent <host:port> --grant <grant>\n"
               "  agent-audit --agent <host:port> [--limit N]\n"
               "  version\n");
}

[[nodiscard]] icf::Result<icf::ClusterId> cluster_arg(Context& context, const char* name) {
  const std::string text = context.arguments.get(name);
  if (text.empty()) {
    return icf::invalid(std::string("missing --") + name);
  }
  return icf::ClusterId::parse(text);
}

[[nodiscard]] icf::Result<icf::EndpointId> endpoint_arg(Context& context, const char* name) {
  const std::string text = context.arguments.get(name);
  if (text.empty()) {
    return icf::invalid(std::string("missing --") + name);
  }
  return icf::EndpointId::parse(text);
}

}  // namespace

int main(int argc, char** argv) {
  icf::Result<icf::app::Arguments> parsed = icf::app::parse_arguments(argc, argv);
  if (!parsed) {
    std::fprintf(stderr, "icfctl: %s\n", parsed.status().message().c_str());
    return 1;
  }
  Context context;
  context.arguments = parsed.value();
  icf::Logger::instance().set_level(icf::LogLevel::Error);

  if (context.arguments.positional.empty() || context.arguments.has("help")) {
    print_usage();
    return context.arguments.has("help") ? 0 : 1;
  }
  const std::string command = context.arguments.positional[0];
  if (command == "version") {
    std::printf("icfctl %s\n", ICF_VERSION_STRING);
    return 0;
  }
  const std::string address = context.arguments.get("connect");
  const std::string key = context.arguments.get("shared_key");
  // Agent-local commands address a cluster agent's own control channel and therefore take
  // --agent instead of --connect.
  const bool agent_command = command.rfind("agent-", 0) == 0;
  if (address.empty() && !agent_command) {
    std::fprintf(stderr, "icfctl: --connect is required\n");
    return 1;
  }

  if (command == "status") {
    icf::wire::QueryMessage query;
    query.kind = icf::wire::QueryKind::Status;
    return run_query(context, address, key, query, [](const icf::wire::QueryResultMessage& result) {
      if (result.status.has_value()) {
        print_status(*result.status, "coordinator");
      } else {
        std::printf("outcome=UNKNOWN\ndetail=the coordinator returned no status\n");
      }
    });
  }
  if (command == "clusters") {
    const std::string sub = context.arguments.positional.size() > 1 ? context.arguments.positional[1] : "list";
    icf::wire::QueryMessage query;
    if (sub == "show") {
      icf::Result<icf::ClusterId> cluster = cluster_arg(context, "cluster");
      if (!cluster) {
        if (context.arguments.positional.size() > 2) {
          cluster = icf::ClusterId::parse(context.arguments.positional[2]);
        }
      }
      if (!cluster) {
        std::fprintf(stderr, "icfctl: clusters show requires a cluster identity\n");
        return 1;
      }
      query.kind = icf::wire::QueryKind::ShowCluster;
      query.cluster = cluster.value();
    } else {
      query.kind = icf::wire::QueryKind::ListClusters;
    }
    return run_query(context, address, key, query, [](const icf::wire::QueryResultMessage& result) {
      for (const icf::model::ClusterRecord& cluster : result.clusters) {
        print_cluster(cluster);
      }
      std::printf("count=%zu\n", result.clusters.size());
    });
  }
  if (command == "links") {
    const std::string sub = context.arguments.positional.size() > 1 ? context.arguments.positional[1] : "list";
    if (sub == "list") {
      icf::wire::QueryMessage query;
      query.kind = icf::wire::QueryKind::ListLinks;
      return run_query(context, address, key, query, [](const icf::wire::QueryResultMessage& result) {
        for (const icf::model::LinkRecord& link : result.links) {
          print_link(link);
        }
        std::printf("count=%zu\n", result.links.size());
      });
    }
    icf::wire::AdminMessage message;
    const std::string id_text = context.arguments.positional.size() > 2 ? context.arguments.positional[2]
                                                                       : context.arguments.get("edge");
    icf::Result<icf::EdgeId> edge = icf::EdgeId::parse(id_text);
    if (!edge) {
      std::fprintf(stderr, "icfctl: links %s requires a link identity\n", sub.c_str());
      return 1;
    }
    if (sub == "add") {
      icf::model::LinkRecord link;
      link.id = edge.value();
      icf::Result<icf::EndpointId> a = endpoint_arg(context, "a");
      icf::Result<icf::EndpointId> b = endpoint_arg(context, "b");
      if (!a || !b) {
        std::fprintf(stderr, "icfctl: links add requires --a and --b endpoint scopes\n");
        return 1;
      }
      link.a = a.value();
      link.b = b.value();
      const std::string kind = context.arguments.get("kind", "synthetic");
      if (kind == "loopback") {
        link.kind = icf::model::LinkKind::LoopbackTcp;
      } else if (kind == "synthetic") {
        link.kind = icf::model::LinkKind::SyntheticModel;
      } else if (kind == "optical") {
        link.kind = icf::model::LinkKind::OpticalInterconnect;
      } else {
        std::fprintf(stderr, "icfctl: --kind must be loopback, synthetic, or optical\n");
        return 1;
      }
      link.capacity = icf::CapacityUnits(context.arguments.get_u64("capacity").has_value()
                                             ? context.arguments.get_u64("capacity").value()
                                             : 1000);
      link.state = icf::model::LinkState::Up;
      link.provenance = admin_provenance();
      message.action = icf::wire::AdminAction::UpsertLink;
      message.link = link;
      return run_admin(context, address, key, message);
    }
    message.action = sub == "fail"     ? icf::wire::AdminAction::SetLinkState
                     : sub == "restore" ? icf::wire::AdminAction::SetLinkState
                     : sub == "degrade" ? icf::wire::AdminAction::SetLinkState
                                        : icf::wire::AdminAction::DeleteLink;
    message.action = sub == "delete" ? icf::wire::AdminAction::DeleteLink : message.action;
    message.edge = edge.value();
    message.link_state = sub == "fail"      ? icf::model::LinkState::Down
                         : sub == "restore" ? icf::model::LinkState::Up
                         : sub == "degrade" ? icf::model::LinkState::Degraded
                                            : icf::model::LinkState::Unknown;
    if (sub != "fail" && sub != "restore" && sub != "degrade" && sub != "delete") {
      std::fprintf(stderr, "icfctl: unknown links subcommand '%s'\n", sub.c_str());
      return 1;
    }
    return run_admin(context, address, key, message);
  }
  if (command == "paths") {
    const std::string sub = context.arguments.positional.size() > 1 ? context.arguments.positional[1] : "list";
    if (sub == "list") {
      icf::wire::QueryMessage query;
      query.kind = icf::wire::QueryKind::ListPaths;
      return run_query(context, address, key, query, [](const icf::wire::QueryResultMessage& result) {
        for (const icf::model::PathRecord& path : result.paths) {
          print_path(path);
        }
        std::printf("count=%zu\n", result.paths.size());
      });
    }
    const std::string id_text = context.arguments.positional.size() > 2 ? context.arguments.positional[2] : "";
    icf::Result<icf::PathId> path = icf::PathId::parse(id_text);
    if (!path) {
      std::fprintf(stderr, "icfctl: paths %s requires a path identity\n", sub.c_str());
      return 1;
    }
    icf::wire::AdminMessage message;
    if (sub == "delete") {
      message.action = icf::wire::AdminAction::DeletePath;
      message.edge = icf::EdgeId::unchecked(path.value().str());
      return run_admin(context, address, key, message);
    }
    icf::model::PathRecord record;
    record.id = path.value();
    icf::Result<icf::EndpointId> a = endpoint_arg(context, "a");
    icf::Result<icf::EndpointId> b = endpoint_arg(context, "b");
    if (!a || !b) {
      std::fprintf(stderr, "icfctl: paths add requires --a and --b endpoint scopes\n");
      return 1;
    }
    record.a = a.value();
    record.b = b.value();
    const std::string hops = context.arguments.get("hops");
    if (hops.empty()) {
      std::fprintf(stderr, "icfctl: paths add requires --hops e1,e2\n");
      return 1;
    }
    std::size_t begin = 0;
    while (begin <= hops.size()) {
      const std::size_t comma = hops.find(',', begin);
      const std::string token = hops.substr(begin, comma == std::string::npos ? std::string::npos : comma - begin);
      if (!token.empty()) {
        icf::Result<icf::EdgeId> hop = icf::EdgeId::parse(token);
        if (!hop) {
          std::fprintf(stderr, "icfctl: invalid hop '%s'\n", token.c_str());
          return 1;
        }
        record.hops.push_back(hop.value());
      }
      if (comma == std::string::npos) {
        break;
      }
      begin = comma + 1;
    }
    record.provenance = admin_provenance();
    message.action = icf::wire::AdminAction::UpsertPath;
    message.path = record;
    return run_admin(context, address, key, message);
  }
  if (command == "policies") {
    const std::string sub = context.arguments.positional.size() > 1 ? context.arguments.positional[1] : "list";
    if (sub == "list") {
      icf::wire::QueryMessage query;
      query.kind = icf::wire::QueryKind::ListPolicies;
      return run_query(context, address, key, query, [](const icf::wire::QueryResultMessage& result) {
        for (const icf::model::PolicyRule& rule : result.policies) {
          print_policy(rule);
        }
        std::printf("count=%zu\n", result.policies.size());
      });
    }
    icf::wire::AdminMessage message;
    if (sub == "delete") {
      const std::string id = context.arguments.positional.size() > 2 ? context.arguments.positional[2] : "";
      if (id.empty()) {
        std::fprintf(stderr, "icfctl: policies delete requires a rule identity\n");
        return 1;
      }
      message.action = icf::wire::AdminAction::DeletePolicy;
      message.policy_id = id;
      return run_admin(context, address, key, message);
    }
    const std::string id = context.arguments.positional.size() > 2 ? context.arguments.positional[2] : "";
    if (id.empty()) {
      std::fprintf(stderr, "icfctl: policies %s requires a rule identity\n", sub.c_str());
      return 1;
    }
    if (sub != "allow" && sub != "refuse") {
      std::fprintf(stderr, "icfctl: unknown policies subcommand '%s'\n", sub.c_str());
      return 1;
    }
    icf::model::PolicyRule rule;
    rule.id = id;
    icf::Result<icf::AuthorityDomainId> owner = icf::AuthorityDomainId::parse(context.arguments.get("owner"));
    if (!owner) {
      std::fprintf(stderr, "icfctl: policies %s requires --owner <domain>\n", sub.c_str());
      return 1;
    }
    rule.owner = owner.value();
    rule.allow = sub == "allow";
    rule.allow_degraded = context.arguments.get("degraded", "false") == "true";
    const std::string a = context.arguments.get("a");
    const std::string b = context.arguments.get("b");
    if (!a.empty()) {
      icf::Result<icf::ClusterId> cluster = icf::ClusterId::parse(a);
      if (!cluster) {
        std::fprintf(stderr, "icfctl: invalid --a cluster\n");
        return 1;
      }
      rule.cluster_a = cluster.value();
    }
    if (!b.empty()) {
      icf::Result<icf::ClusterId> cluster = icf::ClusterId::parse(b);
      if (!cluster) {
        std::fprintf(stderr, "icfctl: invalid --b cluster\n");
        return 1;
      }
      rule.cluster_b = cluster.value();
    }
    const std::string endpoint_a = context.arguments.get("endpoint");
    const std::string endpoint_b = context.arguments.get("endpoint-b");
    if (!endpoint_a.empty()) {
      icf::Result<icf::EndpointId> endpoint = icf::EndpointId::parse(endpoint_a);
      if (!endpoint) {
        return 1;
      }
      rule.endpoint_a = endpoint.value();
    }
    if (!endpoint_b.empty()) {
      icf::Result<icf::EndpointId> endpoint = icf::EndpointId::parse(endpoint_b);
      if (!endpoint) {
        return 1;
      }
      rule.endpoint_b = endpoint.value();
    }
    rule.generation = icf::PolicyGeneration(context.arguments.get_u64("generation").has_value()
                                                ? context.arguments.get_u64("generation").value()
                                                : 1);
    rule.max_capacity = icf::CapacityUnits(context.arguments.get_u64("max-capacity").has_value()
                                               ? context.arguments.get_u64("max-capacity").value()
                                               : 0);
    rule.provenance = admin_provenance();
    message.action = icf::wire::AdminAction::UpsertPolicy;
    message.policy = rule;
    return run_admin(context, address, key, message);
  }
  if (command == "contracts") {
    const std::string sub = context.arguments.positional.size() > 1 ? context.arguments.positional[1] : "list";
    icf::wire::QueryMessage query;
    if (sub == "show") {
      const std::string id = context.arguments.positional.size() > 2 ? context.arguments.positional[2]
                                                                    : context.arguments.get("contract");
      icf::Result<icf::ContractId> contract = icf::ContractId::parse(id);
      if (!contract) {
        std::fprintf(stderr, "icfctl: contracts show requires a contract identity\n");
        return 1;
      }
      query.kind = icf::wire::QueryKind::ShowContract;
      query.contract = contract.value();
    } else {
      query.kind = icf::wire::QueryKind::ListContracts;
    }
    return run_query(context, address, key, query, [](const icf::wire::QueryResultMessage& result) {
      for (const icf::model::ContractRecord& contract : result.contracts) {
        print_contract(contract);
      }
      std::printf("count=%zu\n", result.contracts.size());
    });
  }
  if (command == "grants") {
    const std::string sub = context.arguments.positional.size() > 1 ? context.arguments.positional[1] : "list";
    icf::wire::QueryMessage query;
    if (sub == "show") {
      const std::string id = context.arguments.positional.size() > 2 ? context.arguments.positional[2]
                                                                    : context.arguments.get("grant");
      icf::Result<icf::GrantId> grant = icf::GrantId::parse(id);
      if (!grant) {
        std::fprintf(stderr, "icfctl: grants show requires a grant identity\n");
        return 1;
      }
      query.kind = icf::wire::QueryKind::ShowGrant;
      query.grant = grant.value();
    } else {
      query.kind = icf::wire::QueryKind::ListGrants;
    }
    return run_query(context, address, key, query, [](const icf::wire::QueryResultMessage& result) {
      for (const icf::model::GrantRecord& grant : result.grants) {
        print_grant(grant);
      }
      std::printf("count=%zu\n", result.grants.size());
    });
  }
  if (command == "propose") {
    icf::Result<icf::ClusterId> a = cluster_arg(context, "a");
    icf::Result<icf::ClusterId> b = cluster_arg(context, "b");
    icf::Result<icf::EndpointId> endpoint_a = endpoint_arg(context, "endpoint");
    icf::Result<icf::EndpointId> endpoint_b = endpoint_arg(context, "endpoint-b");
    if (!a || !b || !endpoint_a || !endpoint_b) {
      std::fprintf(stderr, "icfctl: propose requires --a, --endpoint, --b, and --endpoint-b\n");
      return 1;
    }
    icf::wire::AdminMessage message;
    message.action = icf::wire::AdminAction::AuthorizeContract;
    message.cluster_id = a.value();
    message.cluster_b = b.value();
    message.endpoint = endpoint_a.value();
    message.endpoint_b = endpoint_b.value();
    const std::string capacity = context.arguments.get("capacity");
    if (!capacity.empty()) {
      message.capacity = icf::CapacityUnits(context.arguments.get_u64("capacity").value());
    }
    icf::Duration lease = icf::Duration::from_seconds(120);
    const std::string lease_text = context.arguments.get("lease");
    if (!lease_text.empty()) {
      icf::Result<icf::Duration> lease_value = icf::Duration::parse(lease_text);
      if (!lease_value) {
        std::fprintf(stderr, "icfctl: %s\n", lease_value.status().message().c_str());
        return 1;
      }
      lease = lease_value.value();
    }
    message.lease_duration = lease;
    return run_admin(context, address, key, message);
  }
  if (command == "grant" || command == "revalidate" || command == "fence") {
    const std::string id = command == "grant" ? context.arguments.get("contract") : context.arguments.get("grant");
    if (command == "grant") {
      icf::Result<icf::ContractId> contract = icf::ContractId::parse(id);
      if (!contract) {
        std::fprintf(stderr, "icfctl: grant requires --contract <id>\n");
        return 1;
      }
      icf::wire::AdminMessage message;
      message.action = icf::wire::AdminAction::IssueGrant;
      message.contract = contract.value();
      const std::string capacity = context.arguments.get("capacity");
      if (!capacity.empty()) {
        message.capacity = icf::CapacityUnits(context.arguments.get_u64("capacity").value());
      }
      return run_admin(context, address, key, message);
    }
    icf::Result<icf::GrantId> grant = icf::GrantId::parse(id);
    if (!grant) {
      std::fprintf(stderr, "icfctl: %s requires --grant <id>\n", command.c_str());
      return 1;
    }
    icf::wire::AdminMessage message;
    message.action = command == "revalidate" ? icf::wire::AdminAction::RevalidateGrant
                                             : icf::wire::AdminAction::FenceGrant;
    message.grant = grant.value();
    return run_admin(context, address, key, message);
  }
  if (command == "decide") {
    icf::Result<icf::EndpointId> source = endpoint_arg(context, "src");
    icf::Result<icf::EndpointId> target = endpoint_arg(context, "dst");
    if (!source || !target) {
      std::fprintf(stderr, "icfctl: decide requires --src and --dst endpoint scopes\n");
      return 1;
    }
    icf::wire::QueryMessage query;
    query.kind = icf::wire::QueryKind::Decide;
    query.endpoint = source.value();
    query.endpoint_b = target.value();
    const std::string capacity = context.arguments.get("capacity");
    query.capacity = icf::CapacityUnits(capacity.empty() ? 1 : context.arguments.get_u64("capacity").value());
    query.allow_degraded = context.arguments.get("allow-degraded", "false") == "true";
    if (context.arguments.has("expect-src-generation")) {
      query.expect_source_generation = true;
      query.source_generation = icf::Generation(context.arguments.get_u64("expect-src-generation").value());
    }
    if (context.arguments.has("expect-dst-generation")) {
      query.expect_target_generation = true;
      query.target_generation = icf::Generation(context.arguments.get_u64("expect-dst-generation").value());
    }
    return run_query(context, address, key, query, [](const icf::wire::QueryResultMessage& result) {
      if (result.decision.has_value()) {
        print_decision(*result.decision);
      }
    });
  }
  if (command == "fence-plan") {
    icf::Result<icf::ClusterId> cluster = cluster_arg(context, "cluster");
    if (!cluster) {
      std::fprintf(stderr, "icfctl: fence-plan requires --cluster <id>\n");
      return 1;
    }
    icf::wire::QueryMessage query;
    query.kind = icf::wire::QueryKind::FencePlan;
    query.cluster = cluster.value();
    const std::string trigger = context.arguments.get("trigger", "manual");
    query.limit = trigger == "reincarnation" ? 1u
                  : trigger == "withdrawal"  ? 2u
                  : trigger == "policy"      ? 3u
                  : trigger == "coordinator" ? 4u
                                             : 0u;
    return run_query(context, address, key, query, [](const icf::wire::QueryResultMessage& result) {
      if (result.fence_plan.has_value()) {
        print_fence_plan(*result.fence_plan);
      }
    });
  }
  if (command == "withdraw" || command == "resolve") {
    icf::Result<icf::ClusterId> cluster = cluster_arg(context, "cluster");
    if (!cluster) {
      std::fprintf(stderr, "icfctl: %s requires --cluster <id>\n", command.c_str());
      return 1;
    }
    icf::wire::AdminMessage message;
    message.cluster_id = cluster.value();
    message.reason = context.arguments.get("reason", "operator request");
    if (command == "withdraw") {
      message.action = icf::wire::AdminAction::WithdrawConsent;
    } else {
      message.action = icf::wire::AdminAction::ResolveConflict;
      message.generation = icf::Generation(context.arguments.get_u64("generation").value_or(0));
    }
    return run_admin(context, address, key, message);
  }
  if (command == "accounting" || command == "audit") {
    icf::wire::QueryMessage query;
    query.kind = command == "accounting" ? icf::wire::QueryKind::Accounting : icf::wire::QueryKind::ListAudit;
    query.limit = static_cast<std::uint32_t>(context.arguments.get_u64("limit").value_or(64));
    return run_query(context, address, key, query, [command](const icf::wire::QueryResultMessage& result) {
      if (command == "accounting") {
        for (const icf::model::AccountingEntry& entry : result.accounting) {
          std::printf("grant=%s contract=%s endpoint=%s cluster=%s reserved=%llu released=%llu closed=%s\n",
                      entry.grant.to_string().c_str(), entry.contract.to_string().c_str(), entry.endpoint.c_str(),
                      entry.cluster.c_str(), static_cast<unsigned long long>(entry.reserved.value()),
                      static_cast<unsigned long long>(entry.released.value()), entry.closed ? "true" : "false");
        }
        std::printf("count=%zu\n", result.accounting.size());
      } else {
        for (const icf::model::AuditRecord& record : result.audit) {
          std::printf("seq=%llu at=%s actor=%s action=%s subject=%s outcome=%s detail=%s\n",
                      static_cast<unsigned long long>(record.sequence.value()), record.at.to_iso8601().c_str(),
                      record.actor.c_str(), record.action.c_str(), record.subject.c_str(),
                      icf::to_string(record.outcome), record.detail.c_str());
        }
        std::printf("count=%zu\n", result.audit.size());
      }
    });
  }
  if (agent_command) {
    const std::string agent_address = context.arguments.get("agent");
    if (agent_address.empty()) {
      std::fprintf(stderr, "icfctl: %s requires --agent <host:port>\n", command.c_str());
      return 1;
    }
    if (command == "agent-status" || command == "agent-grants" || command == "agent-audit") {
      icf::wire::QueryMessage query;
      query.kind = command == "agent-status"  ? icf::wire::QueryKind::Status
                   : command == "agent-grants" ? icf::wire::QueryKind::ListGrants
                                               : icf::wire::QueryKind::ListAudit;
      query.limit = static_cast<std::uint32_t>(context.arguments.get_u64("limit").value_or(64));
      return run_query(context, agent_address, "", query, [command](const icf::wire::QueryResultMessage& result) {
        if (command == "agent-status") {
          if (result.status.has_value()) {
            print_status(*result.status, "cluster-agent");
          }
          return;
        }
        if (command == "agent-grants") {
          for (const icf::model::GrantRecord& grant : result.grants) {
            print_grant(grant);
          }
          std::printf("count=%zu\n", result.grants.size());
          return;
        }
        for (const icf::model::AuditRecord& record : result.audit) {
          std::printf("seq=%llu action=%s subject=%s outcome=%s detail=%s\n",
                      static_cast<unsigned long long>(record.sequence.value()), record.action.c_str(),
                      record.subject.c_str(), icf::to_string(record.outcome), record.detail.c_str());
        }
        std::printf("count=%zu\n", result.audit.size());
      });
    }
    icf::wire::AdminMessage message;
    if (command == "agent-show") {
      icf::Result<icf::GrantId> grant = icf::GrantId::parse(context.arguments.get("grant"));
      if (!grant) {
        std::fprintf(stderr, "icfctl: agent-show requires --grant <id>\n");
        return 1;
      }
      icf::wire::QueryMessage query;
      query.kind = icf::wire::QueryKind::ShowGrant;
      query.grant = grant.value();
      return run_query(context, agent_address, "", query, [](const icf::wire::QueryResultMessage& result) {
        for (const icf::model::GrantRecord& grant : result.grants) {
          print_grant(grant);
        }
        if (!result.detail.empty()) {
          std::printf("detail=%s\n", result.detail.c_str());
        }
      });
    }
    if (command == "agent-withdraw") {
      message.action = icf::wire::AdminAction::WithdrawConsent;
      message.reason = context.arguments.get("reason", "operator request");
    } else if (command == "agent-state") {
      const std::string state = context.arguments.get("state");
      if (state == "active") {
        message.cluster_state = icf::model::ClusterState::Active;
      } else if (state == "suspended") {
        message.cluster_state = icf::model::ClusterState::Suspended;
      } else if (state == "draining") {
        message.cluster_state = icf::model::ClusterState::Draining;
      } else {
        std::fprintf(stderr, "icfctl: --state must be active, suspended, or draining\n");
        return 1;
      }
      message.action = icf::wire::AdminAction::SetClusterState;
    } else if (command == "agent-bump") {
      icf::Result<icf::GrantId> grant = icf::GrantId::parse("00000000-0000-4000-8000-000000000000");
      message.action = icf::wire::AdminAction::SetClusterState;
      message.cluster_state = icf::model::ClusterState::Active;
      std::fprintf(stderr,
                   "icfctl: agent-bump is not exposed over the wire; bump the generation by restarting the agent "
                   "with --generation\n");
      return 1;
    } else if (command == "agent-fence") {
      icf::Result<icf::GrantId> grant = icf::GrantId::parse(context.arguments.get("grant"));
      if (!grant) {
        std::fprintf(stderr, "icfctl: agent-fence requires --grant <id>\n");
        return 1;
      }
      message.action = icf::wire::AdminAction::FenceGrant;
      message.grant = grant.value();
      message.reason = context.arguments.get("reason", "operator request");
    } else {
      std::fprintf(stderr, "icfctl: unknown agent command '%s'\n", command.c_str());
      return 1;
    }
    return run_admin(context, agent_address, "", message);
  }

  std::fprintf(stderr, "icfctl: unknown command '%s'\n", command.c_str());
  print_usage();
  return 1;
}
