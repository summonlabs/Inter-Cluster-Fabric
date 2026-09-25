# Examples are built by default and consumed by the documentation walkthrough.

add_executable(icf_example_inspect inspect_authority/main.cpp)
target_link_libraries(icf_example_inspect PRIVATE icf::icf)
icf_set_warnings(icf_example_inspect)

install(TARGETS icf_example_inspect RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
