// CLI tests: the operator tooling against real daemon processes.
#include <string>

#include "fleet.hpp"
#include "harness.hpp"

using namespace icf;
using namespace icf::test;

namespace {

AgentSpec cli_agent(const std::string& cluster, const std::string& domain, const std::string& endpoint_id,
                    const std::string& scope) {
  AgentSpec spec;
  spec.cluster = cluster;
  spec.domain = domain;
  spec.generation = 1;
  spec.endpoint_lines = {"endpoint." + endpoint_id + ".scope = " + scope,
                         "endpoint." + endpoint_id + ".capacity = 500",
                         "endpoint." + endpoint_id + ".degraded = true"};
  return spec;
}

}  // namespace

ICF_TEST(cli, status_and_inspection_commands_report_typed_output) {
  Fleet fleet("cli-status");
  ICF_ASSERT_OK(fleet.start_coordinator().status());
  ICF_ASSERT_OK(fleet.start_agent(cli_agent("cluster-a", "domain-north", "a-scope", "/north/a")).status());
  ICF_ASSERT_OK(fleet.wait_for_registration("cluster-a", Duration::from_seconds(20)));

  const std::string connect = "127.0.0.1:" + std::to_string(fleet.coordinator_port());
  Result<std::pair<int, std::string>> status = run_command(fleet.executable("icfctl"),
                                                           {"--connect", connect, "status"}, Duration::from_seconds(20),
                                                           fleet.root());
  ICF_ASSERT_OK(status.status());
  ICF_EXPECT_EQ(0, status.value().first);
  ICF_EXPECT_TRUE(status.value().second.find("role=coordinator") != std::string::npos);
  ICF_EXPECT_TRUE(status.value().second.find("domain=domain-north") != std::string::npos);
  ICF_EXPECT_TRUE(status.value().second.find("term=") != std::string::npos);

  Result<std::pair<int, std::string>> clusters =
      run_command(fleet.executable("icfctl"), {"--connect", connect, "clusters", "list"}, Duration::from_seconds(20),
                  fleet.root());
  ICF_ASSERT_OK(clusters.status());
  ICF_EXPECT_EQ(0, clusters.value().first);
  ICF_EXPECT_TRUE(clusters.value().second.find("cluster=cluster-a") != std::string::npos);
  ICF_EXPECT_TRUE(clusters.value().second.find("endpoint=a-scope") != std::string::npos);

  Result<std::pair<int, std::string>> version =
      run_command(fleet.executable("icfctl"), {"version"}, Duration::from_seconds(20), fleet.root());
  ICF_ASSERT_OK(version.status());
  ICF_EXPECT_EQ(0, version.value().first);
  ICF_EXPECT_TRUE(version.value().second.find("icfctl") != std::string::npos);
}

ICF_TEST(cli, decide_exit_codes_distinguish_authorized_refused_and_unknown) {
  Fleet fleet("cli-decide");
  ICF_ASSERT_OK(fleet.start_coordinator().status());
  ICF_ASSERT_OK(fleet.start_agent(cli_agent("cluster-a", "domain-north", "a-scope", "/north/a")).status());
  ICF_ASSERT_OK(fleet.start_agent(cli_agent("cluster-b", "domain-south", "b-scope", "/south/b")).status());
  ICF_ASSERT_OK(fleet.wait_for_registration("cluster-a", Duration::from_seconds(20)));
  ICF_ASSERT_OK(fleet.wait_for_registration("cluster-b", Duration::from_seconds(20)));
  ICF_ASSERT_OK(fleet.bootstrap_pair("cluster-a", "cluster-b", "a-scope", "b-scope"));

  const std::string connect = "127.0.0.1:" + std::to_string(fleet.coordinator_port());
  Result<std::pair<int, std::string>> unauthorized =
      run_command(fleet.executable("icfctl"),
                  {"--connect", connect, "decide", "--src", "a-scope", "--dst", "b-scope"}, Duration::from_seconds(20),
                  fleet.root());
  ICF_ASSERT_OK(unauthorized.status());
  ICF_EXPECT_EQ(4, unauthorized.value().first);
  ICF_EXPECT_TRUE(unauthorized.value().second.find("outcome=UNAUTHORIZED") != std::string::npos);

  Result<std::pair<int, std::string>> missing =
      run_command(fleet.executable("icfctl"),
                  {"--connect", connect, "decide", "--src", "ghost", "--dst", "b-scope"}, Duration::from_seconds(20),
                  fleet.root());
  ICF_ASSERT_OK(missing.status());
  ICF_EXPECT_EQ(4, missing.value().first);
  ICF_EXPECT_TRUE(missing.value().second.find("outcome=NOT_FOUND") != std::string::npos);

  // Establish real connectivity and check that the CLI reports it as authorized.
  ICF_ASSERT_OK(fleet.establish_grant("cluster-a", "cluster-b", "a-scope", "b-scope"));
  const Status authorized = fleet.wait_until(
      [&]() -> Status {
        Result<std::pair<int, std::string>> result =
            run_command(fleet.executable("icfctl"),
                        {"--connect", connect, "decide", "--src", "a-scope", "--dst", "b-scope"},
                        Duration::from_seconds(20), fleet.root());
        if (!result) {
          return result.status();
        }
        if (result.value().first != 0) {
          return Status::make(Outcome::Indeterminate, "the CLI reported: " + result.value().second);
        }
        return Status::ok();
      },
      Duration::from_seconds(30), "the CLI to report an authorized decision");
  if (!authorized) {
    ICF_FAIL("the CLI never reported an authorized decision: " + authorized.message() + "\ncoordinator log:\n" +
             fleet.coordinator_log());
  }

  Result<std::pair<int, std::string>> ok =
      run_command(fleet.executable("icfctl"),
                  {"--connect", connect, "decide", "--src", "a-scope", "--dst", "b-scope"}, Duration::from_seconds(20),
                  fleet.root());
  ICF_ASSERT_OK(ok.status());
  ICF_EXPECT_EQ(0, ok.value().first);
  ICF_EXPECT_TRUE(ok.value().second.find("outcome=OK") != std::string::npos);
  ICF_EXPECT_TRUE(ok.value().second.find("authorities=domain-north,domain-south") != std::string::npos);
  ICF_EXPECT_TRUE(ok.value().second.find("grant=") != std::string::npos);

  // A policy refusal is reported as REFUSED, which is distinct from UNAUTHORIZED.
  Result<std::pair<int, std::string>> refused =
      run_command(fleet.executable("icfctl"),
                  {"--connect", connect, "policies", "refuse", "cli-refuse", "--owner", "domain-south",
                   "--a", "cluster-a", "--b", "cluster-b"},
                  Duration::from_seconds(20), fleet.root());
  ICF_ASSERT_OK(refused.status());
  ICF_EXPECT_EQ(0, refused.value().first);
  Result<std::pair<int, std::string>> refused_decision =
      run_command(fleet.executable("icfctl"),
                  {"--connect", connect, "decide", "--src", "a-scope", "--dst", "b-scope"}, Duration::from_seconds(20),
                  fleet.root());
  ICF_ASSERT_OK(refused_decision.status());
  ICF_EXPECT_EQ(4, refused_decision.value().first);
  ICF_EXPECT_TRUE(refused_decision.value().second.find("outcome=REFUSED") != std::string::npos);
}

ICF_TEST(cli, link_and_fence_plan_inspection) {
  Fleet fleet("cli-fence-plan");
  ICF_ASSERT_OK(fleet.start_coordinator().status());
  ICF_ASSERT_OK(fleet.start_agent(cli_agent("cluster-a", "domain-north", "a-scope", "/north/a")).status());
  ICF_ASSERT_OK(fleet.start_agent(cli_agent("cluster-b", "domain-south", "b-scope", "/south/b")).status());
  ICF_ASSERT_OK(fleet.wait_for_registration("cluster-a", Duration::from_seconds(20)));
  ICF_ASSERT_OK(fleet.wait_for_registration("cluster-b", Duration::from_seconds(20)));
  ICF_ASSERT_OK(fleet.bootstrap_pair("cluster-a", "cluster-b", "a-scope", "b-scope"));
  ICF_ASSERT_OK(fleet.establish_grant("cluster-a", "cluster-b", "a-scope", "b-scope"));
  const Status authorized = fleet.wait_until(
      [&]() -> Status {
        Result<model::Decision> decision = fleet.decide("a-scope", "b-scope");
        if (!decision) {
          return decision.status();
        }
        return decision.value().authorized() ? Status::ok()
                                             : Status::make(decision.value().outcome, decision.value().detail);
      },
      Duration::from_seconds(30), "authorization");
  ICF_ASSERT_OK(authorized);

  const std::string connect = "127.0.0.1:" + std::to_string(fleet.coordinator_port());
  Result<std::pair<int, std::string>> plan =
      run_command(fleet.executable("icfctl"),
                  {"--connect", connect, "fence-plan", "--cluster", "cluster-b", "--trigger", "reincarnation"},
                  Duration::from_seconds(20), fleet.root());
  ICF_ASSERT_OK(plan.status());
  ICF_EXPECT_EQ(0, plan.value().first);
  ICF_EXPECT_TRUE(plan.value().second.find("trigger=CLUSTER_REINCARNATION") != std::string::npos);
  ICF_EXPECT_TRUE(plan.value().second.find("actions=") != std::string::npos);
  ICF_EXPECT_TRUE(plan.value().second.find("action=GRANT") != std::string::npos);

  Result<std::pair<int, std::string>> links =
      run_command(fleet.executable("icfctl"), {"--connect", connect, "links", "fail", "cluster-a-cluster-b"},
                  Duration::from_seconds(20), fleet.root());
  ICF_ASSERT_OK(links.status());
  ICF_EXPECT_EQ(0, links.value().first);

  Result<std::pair<int, std::string>> decide =
      run_command(fleet.executable("icfctl"),
                  {"--connect", connect, "decide", "--src", "a-scope", "--dst", "b-scope"}, Duration::from_seconds(20),
                  fleet.root());
  ICF_ASSERT_OK(decide.status());
  ICF_EXPECT_EQ(4, decide.value().first);
  ICF_EXPECT_TRUE(decide.value().second.find("outcome=PARTITIONED") != std::string::npos);

  Result<std::pair<int, std::string>> restore =
      run_command(fleet.executable("icfctl"), {"--connect", connect, "links", "restore", "cluster-a-cluster-b"},
                  Duration::from_seconds(20), fleet.root());
  ICF_ASSERT_OK(restore.status());
  ICF_EXPECT_EQ(0, restore.value().first);

  Result<std::pair<int, std::string>> unsupported =
      run_command(fleet.executable("icfctl"),
                  {"--connect", connect, "links", "add", "optical-edge", "--a", "a-scope", "--b", "b-scope",
                   "--kind", "optical"},
                  Duration::from_seconds(20), fleet.root());
  ICF_ASSERT_OK(unsupported.status());
  ICF_EXPECT_EQ(4, unsupported.value().first);
  ICF_EXPECT_TRUE(unsupported.value().second.find("outcome=UNSUPPORTED") != std::string::npos);
}

ICF_TEST(cli, agent_control_channel_reports_local_enforcement) {
  Fleet fleet("cli-agent-control");
  ICF_ASSERT_OK(fleet.start_coordinator().status());
  ICF_ASSERT_OK(fleet.start_agent(cli_agent("cluster-a", "domain-north", "a-scope", "/north/a")).status());
  ICF_ASSERT_OK(fleet.start_agent(cli_agent("cluster-b", "domain-south", "b-scope", "/south/b")).status());
  ICF_ASSERT_OK(fleet.wait_for_registration("cluster-a", Duration::from_seconds(20)));
  ICF_ASSERT_OK(fleet.wait_for_registration("cluster-b", Duration::from_seconds(20)));
  ICF_ASSERT_OK(fleet.bootstrap_pair("cluster-a", "cluster-b", "a-scope", "b-scope"));
  ICF_ASSERT_OK(fleet.establish_grant("cluster-a", "cluster-b", "a-scope", "b-scope"));
  const Status authorized = fleet.wait_until(
      [&]() -> Status {
        Result<model::Decision> decision = fleet.decide("a-scope", "b-scope");
        if (!decision) {
          return decision.status();
        }
        return decision.value().authorized() ? Status::ok()
                                             : Status::make(decision.value().outcome, decision.value().detail);
      },
      Duration::from_seconds(30), "authorization");
  ICF_ASSERT_OK(authorized);

  const std::string agent_address = "127.0.0.1:" + std::to_string(fleet.agent_control_port("cluster-b"));
  Result<std::pair<int, std::string>> status =
      run_command(fleet.executable("icfctl"), {"--agent", agent_address, "agent-status"}, Duration::from_seconds(20),
                  fleet.root());
  ICF_ASSERT_OK(status.status());
  ICF_EXPECT_EQ(0, status.value().first);
  ICF_EXPECT_TRUE(status.value().second.find("role=cluster-agent") != std::string::npos);
  ICF_EXPECT_TRUE(status.value().second.find("connected_agents=1") != std::string::npos);

  Result<std::pair<int, std::string>> grants =
      run_command(fleet.executable("icfctl"), {"--agent", agent_address, "agent-grants"}, Duration::from_seconds(20),
                  fleet.root());
  ICF_ASSERT_OK(grants.status());
  ICF_EXPECT_EQ(0, grants.value().first);
  ICF_EXPECT_TRUE(grants.value().second.find("state=ACTIVE") != std::string::npos);

  Result<std::pair<int, std::string>> audit =
      run_command(fleet.executable("icfctl"), {"--agent", agent_address, "agent-audit"}, Duration::from_seconds(20),
                  fleet.root());
  ICF_ASSERT_OK(audit.status());
  ICF_EXPECT_EQ(0, audit.value().first);
  ICF_EXPECT_TRUE(audit.value().second.find("count=") != std::string::npos);

  // A local control channel must not accept coordinator-only administration. The check goes
  // through the same protocol the CLI uses, so it is the runtime's answer that is asserted.
  {
    Result<client::Client> control = fleet.connect_agent_control("cluster-b");
    ICF_ASSERT_OK(control.status());
    wire::AdminMessage issue;
    issue.action = wire::AdminAction::IssueGrant;
    issue.grant = GrantId::parse("11111111-2222-4333-8444-555555555555").value();
    Result<wire::AdminResultMessage> refused = fleet.admin(control.value(), issue);
    ICF_ASSERT_OK(refused.status());
    ICF_EXPECT_TRUE(refused.value().outcome == Outcome::Unsupported ||
                    refused.value().outcome == Outcome::NotFound);
  }
}
