cmake_minimum_required(VERSION 3.17)
project(sigtool)

IF(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_CXX_FLAGS "-g")
ENDIF()

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 17)

add_library(common OBJECT macho.cpp signature.cpp hash.cpp commands.cpp)
target_include_directories(common PUBLIC vendor)
target_link_libraries(common PRIVATE OpenSSL::Crypto)

add_executable(sigtool main.cpp)
target_link_libraries(sigtool PRIVATE common)

add_executable(codesign codesign.cpp)
target_link_libraries(codesign PRIVATE common)

install(TARGETS sigtool codesign)
