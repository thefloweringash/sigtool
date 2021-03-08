cmake_minimum_required(VERSION 3.17)
project(sigtool)

IF(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_CXX_FLAGS "-g")
ENDIF()

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 11)

add_executable(sigtool main.cpp macho.cpp signature.cpp hash.cpp commands.cpp)
target_link_libraries(sigtool PRIVATE OpenSSL::Crypto)
target_include_directories(sigtool PRIVATE vendor)

install(TARGETS sigtool)
