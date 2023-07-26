cmake_minimum_required(VERSION 3.10)
project(dpdk-tool)

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

get_filename_component(ROOT "${CMAKE_CURRENT_SOURCE_DIR}/" ABSOLUTE)

add_definitions(-DALLOW_EXPERIMENTAL_API -DDALLOW_INTERNAL_API)
add_definitions("-O3 -march=native")

# find dpdk path
include(${ROOT}/cmake/dpdk.cmake)

include_directories(
    ${DPDK_INCLUDE}
    ${ROOT}/include
)

add_subdirectory(dpdkpcap)
add_subdirectory(singlechannel)
add_subdirectory(multichannel)
