#include "harness.hpp"

#include <cstdio>
#include <cstring>
#include <string>

#include "icf/core/rng.hpp"

namespace icf::test {
namespace {

Context& mutable_context() {
  static Context context;
  return context;
}

std::uint64_t& mutable_seed() {
  static std::uint64_t seed = 0;
  return seed;
}

}  // namespace

Registry& Registry::instance() {
  static Registry registry;
  return registry;
}

void Registry::add(const char* suite, const char* name, void (*body)()) {
  cases_.push_back(TestCase{suite, name, body});
}

Context& context() { return mutable_context(); }

std::uint64_t run_seed() {
  if (mutable_seed() == 0) {
    mutable_seed() = entropy_seed();
  }
  return mutable_seed();
}

void set_run_seed(std::uint64_t seed) { mutable_seed() = seed; }

void record_failure(const char* file, int line, const std::string& message) {
  Context& current = mutable_context();
  ++current.failures;
  std::fprintf(stderr, "FAIL %s.%s\n  at %s:%d\n  %s\n", current.suite, current.name, file, line, message.c_str());
  std::fflush(stderr);
}

int run_all(int argc, char** argv) {
  std::string filter;
  std::uint64_t seed = 0;
  bool list_only = false;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--filter" && index + 1 < argc) {
      filter = argv[++index];
    } else if (argument.rfind("--filter=", 0) == 0) {
      filter = argument.substr(9);
    } else if (argument == "--seed" && index + 1 < argc) {
      seed = std::strtoull(argv[++index], nullptr, 10);
    } else if (argument.rfind("--seed=", 0) == 0) {
      seed = std::strtoull(argument.c_str() + 7, nullptr, 10);
    } else if (argument == "--list") {
      list_only = true;
    }
  }
  if (seed != 0) {
    set_run_seed(seed);
  }
  const std::uint64_t effective_seed = run_seed();

  const std::vector<TestCase>& cases = Registry::instance().cases();
  if (list_only) {
    for (const TestCase& test : cases) {
      std::printf("%s.%s\n", test.suite, test.name);
    }
    return 0;
  }
  std::printf("seed=%llu cases=%zu\n", static_cast<unsigned long long>(effective_seed), cases.size());
  std::size_t failed = 0;
  std::size_t executed = 0;
  for (const TestCase& test : cases) {
    const std::string full = std::string(test.suite) + "." + test.name;
    if (!filter.empty() && full.find(filter) == std::string::npos) {
      continue;
    }
    Context& current = mutable_context();
    current.suite = test.suite;
    current.name = test.name;
    current.failures = 0;
    ++executed;
    try {
      test.body();
    } catch (const TestAborted&) {
      // failures already recorded
    } catch (const std::exception& error) {
      record_failure(__FILE__, __LINE__, std::string("unhandled exception: ") + error.what());
    } catch (...) {
      record_failure(__FILE__, __LINE__, "unhandled non-standard exception");
    }
    if (current.failures == 0) {
      std::printf("PASS %s\n", full.c_str());
    } else {
      std::printf("FAILED %s (%zu failure(s))\n", full.c_str(), current.failures);
      ++failed;
    }
    std::fflush(stdout);
  }
  std::printf("TESTS=%zu FAILED=%zu SEED=%llu\n", executed, failed,
              static_cast<unsigned long long>(effective_seed));
  std::fflush(stdout);
  return failed == 0 ? 0 : 1;
}

}  // namespace icf::test

int main(int argc, char** argv) { return ::icf::test::run_all(argc, argv); }
