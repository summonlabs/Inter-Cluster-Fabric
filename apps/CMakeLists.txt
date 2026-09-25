# Daemons and the operator CLI.

set(ICF_APPS icfd icfclusterd icfctl)

add_executable(icfd icfd/main.cpp)
target_link_libraries(icfd PRIVATE icf::icf)
target_include_directories(icfd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)

add_executable(icfclusterd icfclusterd/main.cpp)
target_link_libraries(icfclusterd PRIVATE icf::icf)
target_include_directories(icfclusterd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)

add_executable(icfctl icfctl/main.cpp)
target_link_libraries(icfctl PRIVATE icf::icf)
target_include_directories(icfctl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)

foreach(app ${ICF_APPS})
  icf_set_warnings(${app})
endforeach()

install(TARGETS ${ICF_APPS} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
