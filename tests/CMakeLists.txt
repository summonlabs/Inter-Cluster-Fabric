# Test suite. Every test binary is registered with CTest.
#
# There is deliberately no TIMEOUT property and no watchdog: a hang is a defect in the runtime
# that must be diagnosed and fixed, never masked by killing the test and calling it a pass.

function(icf_add_test name)
  add_executable(${name} support/harness.cpp ${ARGN})
  target_link_libraries(${name} PRIVATE icf::icf)
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/support)
  icf_set_warnings(${name})
  add_test(NAME ${name} COMMAND ${name})
endfunction()

icf_add_test(icf_core_tests unit/core_tests.cpp)
icf_add_test(icf_model_tests unit/model_tests.cpp)
icf_add_test(icf_wire_tests unit/wire_tests.cpp)
icf_add_test(icf_store_tests unit/store_tests.cpp)
icf_add_test(icf_engine_tests unit/engine_tests.cpp)
icf_add_test(icf_policy_tests unit/policy_tests.cpp)
icf_add_test(icf_property_tests property/property_tests.cpp)
icf_add_test(icf_differential_tests differential/differential_tests.cpp)
icf_add_test(icf_adversarial_tests adversarial/adversarial_tests.cpp)
icf_add_test(icf_net_tests net/net_tests.cpp)
icf_add_test(icf_concurrency_tests net/concurrency_tests.cpp)

icf_add_test(icf_multiprocess_tests integration/multiprocess_tests.cpp)
target_compile_definitions(icf_multiprocess_tests PRIVATE
  ICF_BIN_DIR="$<TARGET_FILE_DIR:icfd>"
  ICF_TEST_TMP_DIR="${CMAKE_CURRENT_BINARY_DIR}/tmp")
add_dependencies(icf_multiprocess_tests icfd icfclusterd icfctl)

icf_add_test(icf_cli_tests integration/cli_tests.cpp)
target_compile_definitions(icf_cli_tests PRIVATE
  ICF_BIN_DIR="$<TARGET_FILE_DIR:icfd>"
  ICF_TEST_TMP_DIR="${CMAKE_CURRENT_BINARY_DIR}/tmp")
add_dependencies(icf_cli_tests icfd icfclusterd icfctl)
