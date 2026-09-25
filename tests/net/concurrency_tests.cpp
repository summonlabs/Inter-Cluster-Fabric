// Concurrency and lifecycle tests.
//
// The runtime's hot path is single threaded by design: one event loop owns every socket, every
// connection, and the registry. These tests exercise the boundaries where that design meets
// genuine concurrency - many client threads against one loop, repeated loop start/stop, and
// repeated store open/close - and check that no state is observed torn, no resource leaks, and
// no shutdown hangs.
#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "coordinator_harness.hpp"
#include "harness.hpp"
#include "icf/client/client.hpp"
#include "icf/core/log.hpp"
#include "icf/store/durable_store.hpp"
#include "icf/store/file_util.hpp"
#include "model_builder.hpp"
#include "temp_dir.hpp"

using namespace icf;
using namespace icf::test;

namespace {

wire::QueryResultMessage status_query(client::Client& client, std::uint64_t seed) {
  wire::QueryMessage query;
  query.kind = wire::QueryKind::Status;
  query.request = Uuid::random(*new Rng(seed));
  Result<wire::QueryResultMessage> result = client.query(query);
  if (!result) {
    wire::QueryResultMessage failure;
    failure.outcome = result.status().outcome();
    failure.detail = result.status().message();
    return failure;
  }
  return result.value();
}

}  // namespace

ICF_TEST(concurrency, many_client_threads_against_one_event_loop) {
  CoordinatorHarness harness("concurrency-clients");
  ICF_ASSERT_TRUE(harness.valid());
  constexpr int kThreads = 8;
  constexpr int kPerThread = 25;
  std::atomic<int> failures{0};
  std::atomic<int> successes{0};
  std::atomic<bool> start{false};

  std::vector<std::thread> workers;
  workers.reserve(kThreads);
  for (int thread_index = 0; thread_index < kThreads; ++thread_index) {
    workers.emplace_back([&, thread_index]() {
      while (!start.load()) {
      }
      for (int iteration = 0; iteration < kPerThread; ++iteration) {
        client::ClientOptions options;
        options.host = "127.0.0.1";
        options.port = harness.port();
        Result<client::Client> client = client::Client::connect(options, harness.clock());
        if (!client) {
          ++failures;
          continue;
        }
        const wire::QueryResultMessage result = status_query(
            client.value(), static_cast<std::uint64_t>(thread_index * 1000 + iteration + 1));
        if (result.outcome != Outcome::Ok || !result.status.has_value()) {
          ++failures;
          continue;
        }
        // Every reply must carry a self-consistent view of the coordinator.
        if (result.status->view_digest != harness.coordinator().registry().digest()) {
          ++failures;
          continue;
        }
        ++successes;
      }
    });
  }
  start.store(true);
  for (std::thread& worker : workers) {
    worker.join();
  }
  ICF_EXPECT_EQ(0, failures.load());
  ICF_EXPECT_EQ(kThreads * kPerThread, successes.load());
  ICF_EXPECT_EQ(static_cast<std::size_t>(0), harness.coordinator().sessions().size());
}

ICF_TEST(concurrency, repeated_loop_start_and_stop_cycles) {
  for (int cycle = 0; cycle < 8; ++cycle) {
    CoordinatorHarness harness("concurrency-cycle");
    ICF_ASSERT_TRUE(harness.valid());
    client::ClientOptions options;
    options.host = "127.0.0.1";
    options.port = harness.port();
    Result<client::Client> client = client::Client::connect(options, harness.clock());
    ICF_ASSERT_OK(client.status());
    client.value().close();
    // The harness destructor stops the loop and joins the thread. A hang here would be a defect
    // in the shutdown path, not a test infrastructure problem.
  }
  ICF_EXPECT_TRUE(true);
}

ICF_TEST(concurrency, clients_disconnecting_mid_session_do_not_leak_connections) {
  CoordinatorHarness harness("concurrency-churn");
  ICF_ASSERT_TRUE(harness.valid());
  for (int iteration = 0; iteration < 60; ++iteration) {
    client::ClientOptions options;
    options.host = "127.0.0.1";
    options.port = harness.port();
    Result<client::Client> client = client::Client::connect(options, harness.clock());
    ICF_ASSERT_OK(client.status());
    (void)status_query(client.value(), static_cast<std::uint64_t>(iteration + 1));
    // Abandon the connection without a clean shutdown frame.
    client.value().close();
  }
  // Give the loop a bounded window to reap the closed connections.
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (std::chrono::steady_clock::now() < deadline) {
    client::ClientOptions options;
    options.host = "127.0.0.1";
    options.port = harness.port();
    Result<client::Client> probe = client::Client::connect(options, harness.clock());
    if (probe) {
      const wire::QueryResultMessage result = status_query(probe.value(), 9999);
      if (result.outcome == Outcome::Ok) {
        break;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  const std::size_t open_connections = harness.coordinator().status().connected_agents;
  ICF_EXPECT_TRUE(open_connections <= 2);
}

ICF_TEST(concurrency, store_open_close_cycles_are_clean) {
  TempDir directory("concurrency-store");
  Rng rng(91);
  PairFixture fixture = make_authorized_pair(rng);
  store::DurableStore::Options options;
  options.directory = directory.path();
  options.snapshot_name = "cycle.snapshot";
  options.wal_name = "cycle.wal";
  options.durable = false;
  for (int cycle = 0; cycle < 25; ++cycle) {
    store::DurableStore::Recovery recovery;
    Result<store::DurableStore> store = store::DurableStore::open(options, recovery);
    ICF_ASSERT_OK(store.status());
    store::Mutation mutation;
    mutation.kind = store::MutationKind::ClusterPut;
    mutation.cluster = fixture.source.cluster;
    ICF_ASSERT_OK(store.value().append(mutation, Timestamp::from_unix_nanos(cycle)).status());
    if (cycle % 5 == 0) {
      model::Registry registry;
      ICF_ASSERT_OK(registry.put_cluster(fixture.source.cluster));
      ICF_ASSERT_OK(store.value().compact(registry, store::StoreMeta{}, Timestamp::from_unix_nanos(cycle)));
    }
  }
  store::DurableStore::Recovery recovery;
  Result<store::DurableStore> reopened = store::DurableStore::open(options, recovery);
  ICF_ASSERT_OK(reopened.status());
  ICF_EXPECT_TRUE(recovery.registry.find_cluster(fixture.source.cluster.id) != nullptr);
}

ICF_TEST(concurrency, logger_is_safe_under_concurrent_writers) {
  TempDir directory("concurrency-logger");
  const std::string path = directory.child("icf.log");
  ICF_ASSERT_OK(Logger::instance().set_file(path));
  Logger::instance().set_level(LogLevel::Info);
  constexpr int kThreads = 6;
  constexpr int kLines = 200;
  std::vector<std::thread> workers;
  workers.reserve(kThreads);
  for (int thread_index = 0; thread_index < kThreads; ++thread_index) {
    workers.emplace_back([thread_index]() {
      for (int line = 0; line < kLines; ++line) {
        const std::string thread_text = std::to_string(thread_index);
        const std::string line_text = std::to_string(line);
        const std::initializer_list<std::pair<std::string_view, std::string_view>> fields{
            {"thread", thread_text}, {"line", line_text}};
        ICF_LOG_INFO_KF("concurrency", "concurrent log line", fields);
      }
    });
  }
  for (std::thread& worker : workers) {
    worker.join();
  }
  Logger::instance().set_stream(nullptr);
  Result<std::uint64_t> size = store::file_size(path);
  ICF_EXPECT_TRUE(size.has_value());
  ICF_EXPECT_TRUE(size.value() > 0);
}

ICF_TEST(concurrency, registry_reads_from_many_threads_are_consistent) {
  Rng rng(92);
  PairFixture fixture = make_authorized_pair(rng);
  authorize_pair(fixture, rng);
  model::Registry registry = fixture.registry;
  const Digest expected = registry.digest();
  std::atomic<int> mismatches{0};
  constexpr int kThreads = 8;
  std::vector<std::thread> workers;
  workers.reserve(kThreads);
  for (int thread_index = 0; thread_index < kThreads; ++thread_index) {
    workers.emplace_back([&registry, &mismatches, expected]() {
      for (int iteration = 0; iteration < 40; ++iteration) {
        if (registry.digest() != expected) {
          ++mismatches;
        }
      }
    });
  }
  for (std::thread& worker : workers) {
    worker.join();
  }
  // Concurrent readers of an unmodified registry must all observe the same value. Mutation is
  // owned by the event loop, so this is the read-only side of the ownership rule.
  ICF_EXPECT_EQ(0, mismatches.load());
}
