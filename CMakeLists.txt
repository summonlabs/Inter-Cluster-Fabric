cmake_minimum_required(VERSION 3.20)

project(InterClusterFabric
  VERSION 1.0.0
  DESCRIPTION "Governed connectivity authority between independently managed accelerator clusters"
  HOMEPAGE_URL "https://github.com/summonlabs/Inter-Cluster-Fabric"
  LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(ICF_BUILD_APPS "Build the icfd/icfclusterd daemons and the icfctl CLI" ON)
option(ICF_BUILD_TESTS "Build the ICF test suite" ON)
option(ICF_BUILD_BENCHMARKS "Build the ICF benchmark harness" ON)
option(ICF_BUILD_EXAMPLES "Build ICF examples" ON)
option(ICF_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
option(ICF_ENABLE_ASAN "Build with AddressSanitizer (MSVC /fsanitize=address)" OFF)
option(ICF_ENABLE_TSAN "Build with ThreadSanitizer (unsupported on MSVC)" OFF)

if(ICF_ENABLE_TSAN)
  message(FATAL_ERROR "ICF_ENABLE_TSAN is not supported by this toolchain configuration; see docs/LIMITATIONS.md")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(icf-warnings)

# ---------------------------------------------------------------------------
# Runtime library
# ---------------------------------------------------------------------------
set(ICF_LIB_SOURCES
  src/core/checked.cpp
  src/core/status.cpp
  src/core/utf8.cpp
  src/core/hash.cpp
  src/core/bytes.cpp
  src/core/time.cpp
  src/core/rng.cpp
  src/core/ids.cpp
  src/core/config.cpp
  src/core/log.cpp
  src/model/records.cpp
  src/model/policy.cpp
  src/model/terms.cpp
  src/model/decision.cpp
  src/model/canonical.cpp
  src/model/registry.cpp
  src/wire/frame.cpp
  src/wire/messages.cpp
  src/store/file_util.cpp
  src/store/wal.cpp
  src/store/mutation.cpp
  src/store/snapshot.cpp
  src/store/durable_store.cpp
  src/net/platform.cpp
  src/net/socket.cpp
  src/net/poller.cpp
  src/net/reactor.cpp
  src/runtime/audit.cpp
  src/runtime/engine.cpp
  src/runtime/fencing.cpp
  src/runtime/coordinator.cpp
  src/runtime/agent.cpp
  src/client/client.cpp
  src/version.cpp)

add_library(icf ${ICF_LIB_SOURCES})
add_library(icf::icf ALIAS icf)

configure_file(cmake/version.hpp.in "${CMAKE_CURRENT_BINARY_DIR}/generated/icf/version.hpp" @ONLY)

target_include_directories(icf
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_compile_definitions(icf
  PRIVATE ICF_BUILDING_LIBRARY=1
  PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)

icf_set_warnings(icf)

if(WIN32)
  target_link_libraries(icf PUBLIC ws2_32)
else()
  find_package(Threads REQUIRED)
  target_link_libraries(icf PUBLIC Threads::Threads)
endif()

if(ICF_ENABLE_ASAN)
  if(MSVC)
    # /Zi is required: the sanitizer warns (C5072) without debug information.
    target_compile_options(icf PUBLIC /fsanitize=address /Zi)
    target_link_options(icf PUBLIC /INCREMENTAL:NO)
  else()
    target_compile_options(icf PUBLIC -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(icf PUBLIC -fsanitize=address)
  endif()
endif()

set_target_properties(icf PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  OUTPUT_NAME icf)

# ---------------------------------------------------------------------------
# Install / export
# ---------------------------------------------------------------------------
install(TARGETS icf
  EXPORT icfTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/icf
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.hpp")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/generated/icf/version.hpp"
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/icf)

install(EXPORT icfTargets
  FILE icfTargets.cmake
  NAMESPACE icf::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/icf)

configure_package_config_file(
  cmake/icf-config.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/icf-config.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/icf)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/icf-config-version.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/icf-config.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/icf-config-version.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/icf)

install(FILES LICENSE NOTICE README.md DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/icf)

if(ICF_BUILD_APPS)
  add_subdirectory(apps)
endif()
if(ICF_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
if(ICF_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()
if(ICF_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
