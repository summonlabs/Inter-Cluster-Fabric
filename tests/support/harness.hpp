// Inter-Cluster Fabric - minimal deterministic test harness.
//
// The runtime deliberately depends only on the C++ standard library, so the test suite brings
// its own harness instead of pulling a framework in. A failing seed is always printed, and a
// failure never aborts the process (except for ASSERT variants, which abort the current case).
#pragma once

#include <cstdint>
#include <exception>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

#include "icf/core/hash.hpp"
#include "icf/core/ids.hpp"
#include "icf/core/status.hpp"

namespace icf::test {

struct TestCase {
  const char* suite;
  const char* name;
  void (*body)();
};

class Registry {
 public:
  static Registry& instance();
  void add(const char* suite, const char* name, void (*body)());
  [[nodiscard]] const std::vector<TestCase>& cases() const noexcept { return cases_; }

 private:
  std::vector<TestCase> cases_;
};

class TestAborted : public std::exception {
 public:
  [[nodiscard]] const char* what() const noexcept override { return "test aborted by a failed assertion"; }
};

struct Context {
  const char* suite = "";
  const char* name = "";
  std::size_t failures = 0;
};

[[nodiscard]] Context& context();
void record_failure(const char* file, int line, const std::string& message);
[[nodiscard]] std::uint64_t run_seed();
void set_run_seed(std::uint64_t seed);
[[nodiscard]] int run_all(int argc, char** argv);

// Describes a value for a failure message. Types without a stream operator fall back to a
// placeholder rather than failing to compile.
template <class T>
std::string describe(const T& value) {
  if constexpr (requires(std::ostringstream& stream, const T& candidate) { stream << candidate; }) {
    std::ostringstream stream;
    stream << value;
    return stream.str();
  } else {
    (void)value;
    return "<value of a type without a stream operator>";
  }
}

inline std::string describe(const Status& status) { return status.to_string(); }

// Test macros accept either a Status or a Result<T>: both expose a status. The macro stores the
// status by value: a reference returned through a helper would not extend the temporary's
// lifetime and would dangle after the declaring statement (a defect ASan reports as
// stack-use-after-scope).
[[nodiscard]] inline const Status& as_status(const Status& status) noexcept { return status; }

template <class T>
[[nodiscard]] inline const Status& as_status(const Result<T>& result) noexcept {
  return result.status();
}

inline std::string describe(bool value) { return value ? "true" : "false"; }



#define ICF_TEST(suite_name, case_name)                                                        \
  static void suite_name##_##case_name##_body();                                               \
  namespace {                                                                                  \
  const bool suite_name##_##case_name##_registered =                                           \
      (::icf::test::Registry::instance().add(#suite_name, #case_name,                          \
                                             &suite_name##_##case_name##_body),                \
       true);                                                                                  \
  }                                                                                            \
  static void suite_name##_##case_name##_body()

#define ICF_EXPECT_TRUE(expression)                                                                \
  do {                                                                                             \
    if (!(expression)) {                                                                           \
      ::icf::test::record_failure(__FILE__, __LINE__, std::string("expected true: ") + #expression); \
    }                                                                                              \
  } while (false)

#define ICF_EXPECT_FALSE(expression)                                                               \
  do {                                                                                             \
    if ((expression)) {                                                                            \
      ::icf::test::record_failure(__FILE__, __LINE__, std::string("expected false: ") + #expression); \
    }                                                                                              \
  } while (false)

#define ICF_EXPECT_EQ(expected, actual)                                                              \
  do {                                                                                               \
    const auto icf_expected_value = (expected);                                                      \
    const auto icf_actual_value = (actual);                                                          \
    if (!(icf_expected_value == icf_actual_value)) {                                                 \
      ::icf::test::record_failure(__FILE__, __LINE__,                                                \
                                  std::string(#actual " == " #expected " failed: got '") +           \
                                      ::icf::test::describe(icf_actual_value) + "', expected '" +    \
                                      ::icf::test::describe(icf_expected_value) + "'");              \
    }                                                                                                \
  } while (false)

#define ICF_EXPECT_NE(left, right)                                                                   \
  do {                                                                                               \
    const auto icf_left_value = (left);                                                              \
    const auto icf_right_value = (right);                                                            \
    if (icf_left_value == icf_right_value) {                                                         \
      ::icf::test::record_failure(__FILE__, __LINE__,                                                \
                                  std::string(#left " != " #right " failed: both are '") +           \
                                      ::icf::test::describe(icf_left_value) + "'");                  \
    }                                                                                                \
  } while (false)

#define ICF_EXPECT_OK(status)                                                                        \
  do {                                                                                               \
    const ::icf::Status icf_status_value = ::icf::test::as_status(status);                                                \
    if (!icf_status_value.is_ok()) {                                                                 \
      ::icf::test::record_failure(__FILE__, __LINE__,                                                \
                                  std::string("expected OK from " #status ", got ") +                \
                                      icf_status_value.to_string());                                 \
    }                                                                                                \
  } while (false)

#define ICF_EXPECT_OUTCOME(expected, status)                                                         \
  do {                                                                                               \
    const ::icf::Status icf_status_value = ::icf::test::as_status(status);                                                \
    if (icf_status_value.outcome() != (expected)) {                                                  \
      ::icf::test::record_failure(__FILE__, __LINE__,                                                \
                                  std::string("expected outcome ") + ::icf::to_string(expected) +     \
                                      " from " #status ", got " + icf_status_value.to_string());     \
    }                                                                                                \
  } while (false)

#define ICF_ASSERT_TRUE(expression)                                                                  \
  do {                                                                                               \
    if (!(expression)) {                                                                             \
      ::icf::test::record_failure(__FILE__, __LINE__,                                                \
                                  std::string("assertion failed: ") + #expression);                  \
      throw ::icf::test::TestAborted();                                                              \
    }                                                                                                \
  } while (false)

#define ICF_ASSERT_FALSE(expression)                                                               \
  do {                                                                                             \
    if ((expression)) {                                                                            \
      ::icf::test::record_failure(__FILE__, __LINE__,                                                \
                                  std::string("assertion failed (expected false): ") + #expression); \
      throw ::icf::test::TestAborted();                                                            \
    }                                                                                              \
  } while (false)

#define ICF_ASSERT_OK(status)                                                                        \
  do {                                                                                               \
    const ::icf::Status icf_status_value = ::icf::test::as_status(status);                                                \
    if (!icf_status_value.is_ok()) {                                                                 \
      ::icf::test::record_failure(__FILE__, __LINE__,                                                \
                                  std::string("assertion failed: " #status " -> ") +                 \
                                      icf_status_value.to_string());                                 \
      throw ::icf::test::TestAborted();                                                              \
    }                                                                                                \
  } while (false)

#define ICF_FAIL(message)                                                                            \
  do {                                                                                               \
    ::icf::test::record_failure(__FILE__, __LINE__, std::string(message));                           \
    throw ::icf::test::TestAborted();                                                                \
  } while (false)

}  // namespace icf::test

// Stream operators for the runtime value types, so a failure message names the actual value
// instead of a placeholder. These live in the test harness, never in the runtime.
namespace icf {

inline std::ostream& operator<<(std::ostream& stream, Outcome outcome) { return stream << to_string(outcome); }
inline std::ostream& operator<<(std::ostream& stream, const Uuid& id) { return stream << id.to_string(); }
inline std::ostream& operator<<(std::ostream& stream, const Digest& digest) { return stream << digest.hex(); }

template <class Tag>
inline std::ostream& operator<<(std::ostream& stream, const Name<Tag>& name) { return stream << name.str(); }

template <class Tag>
inline std::ostream& operator<<(std::ostream& stream, const StrongUuid<Tag>& id) {
  return stream << id.to_string();
}

template <class Tag>
inline std::ostream& operator<<(std::ostream& stream, const Counter<Tag>& counter) {
  return stream << counter.value();
}

}  // namespace icf
