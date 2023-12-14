cmake_minimum_required(VERSION 3.25)
project(sing_box_config)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_definitions(QT_NO_KEYWORDS UNICODE _UNICODE NOMINMAX)

# 使用中文
add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

# this is heuristically generated, and may not be correct
# find_package(unofficial-b64)
find_package(Boost COMPONENTS locale url)
find_package(nlohmann_json)
find_package(fmt)
find_package(OpenSSL)
add_executable(sing_box_config
  main.cpp
  resource.h
  win_exe.rc
  sing_box.manifest
)
set(CPACK_GENERATOR 7Z)
set(CPACK_PACKAGE_DIRECTORY ${PROJECT_SOURCE_DIR}/build)
include(CPack)
# target_include_directories(sing_box_config PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(sing_box_config PUBLIC nlohmann_json::nlohmann_json fmt::fmt Boost::locale Boost::url OpenSSL::SSL)

install(TARGETS sing_box_config
  RUNTIME_DEPENDENCIES
  PRE_EXCLUDE_REGEXES "api-ms-" "ext-ms-" "hvsifiletrust" "pdmutilities"
  POST_EXCLUDE_REGEXES ".*system32/.*\\.dll"
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
install(CODE "
include(BundleUtilities)
fixup_bundle(\"$<TARGET_FILE:sing_box_config>\" \"\" \" \")
")