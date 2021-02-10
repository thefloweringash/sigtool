cmake_minimum_required(VERSION 3.18)
project(sigtool)

IF(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_CXX_FLAGS "-g")
ENDIF()

find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL REQUIRED IMPORTED_TARGET openssl)

set(CMAKE_CXX_STANDARD 11)

add_executable(sigtool main.cpp macho.cpp signature.cpp hash.cpp)
target_link_libraries(sigtool PRIVATE PkgConfig::OPENSSL)
target_include_directories(sigtool PRIVATE vendor)

install(TARGETS sigtool)
