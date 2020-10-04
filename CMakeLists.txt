cmake_minimum_required(VERSION 3.18)
project(gensig)

IF(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_CXX_FLAGS "-g")
ENDIF()

# This should be required but upstream's CLI11Config.cmake file doesn't seem to
# be compatible.
# find_package(CLI11 CONFIG REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CRYPTOPP REQUIRED IMPORTED_TARGET libcryptopp)

set(CMAKE_CXX_STANDARD 11)

add_executable(gensig main.cpp macho.cpp signature.cpp)
target_link_libraries(gensig
        PRIVATE
        PkgConfig::CRYPTOPP
        #CLI11:CLI11
        )
