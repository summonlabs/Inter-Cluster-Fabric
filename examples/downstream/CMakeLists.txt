# An independent downstream consumer of the installed icf package.
#
# This project is deliberately not part of the Inter-Cluster Fabric build: it is configured,
# built, and run against an installed prefix with nothing but find_package(icf CONFIG REQUIRED).
cmake_minimum_required(VERSION 3.20)

project(icf-downstream-consumer
  VERSION 1.0.0
  DESCRIPTION "Independent consumer of the installed Inter-Cluster Fabric package"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(icf CONFIG REQUIRED)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE icf::icf)

if(MSVC)
  target_compile_options(consumer PRIVATE /W4 /WX)
  target_compile_definitions(consumer PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
else()
  target_compile_options(consumer PRIVATE -Wall -Wextra -Werror)
endif()

install(TARGETS consumer RUNTIME DESTINATION bin)
