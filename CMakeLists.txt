cmake_minimum_required(VERSION 3.17)
project(sigtool)

IF(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_CXX_FLAGS "-g")
ENDIF()

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 17)

add_library(common OBJECT macho.cpp signature.cpp hash.cpp commands.cpp)
set_property(TARGET common PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(common PUBLIC vendor)
target_link_libraries(common PRIVATE OpenSSL::Crypto)

add_executable(sigtool main.cpp)
target_link_libraries(sigtool PRIVATE common)

add_executable(codesign codesign.cpp)
target_link_libraries(codesign PRIVATE common)

add_library(libsigtool)
target_link_libraries(libsigtool PRIVATE common)
set_property(TARGET libsigtool PROPERTY OUTPUT_NAME sigtool)

install(TARGETS sigtool codesign libsigtool)

install(
  FILES
    commands.h
    emit.h
    hash.h
    macho.h
    signature.h
  DESTINATION
    include/sigtool
)
