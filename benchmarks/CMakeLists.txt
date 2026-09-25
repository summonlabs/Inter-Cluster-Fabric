add_executable(icf-bench bench_main.cpp)
target_link_libraries(icf-bench PRIVATE icf::icf)
target_include_directories(icf-bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../apps/common)
icf_set_warnings(icf-bench)

install(TARGETS icf-bench RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
