cmake_minimum_required(VERSION 3.16)

project(PcapAnalyzer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(network_lib
    src/net/capture/pcap.cpp
    src/net/protocols/ethernet.cpp
    src/net/protocols/ipv4.cpp
    src/net/protocols/ipv6.cpp
    src/net/protocols/tcp.cpp
    src/net/protocols/udp.cpp
)

target_include_directories(network_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(analyzer
    src/main.cpp
)

target_link_libraries(analyzer
    PRIVATE
        network_lib
)

enable_testing()

find_package(GTest REQUIRED)
include(GoogleTest)

add_executable(tests
    tests/test_basic.cpp
)

target_link_libraries(tests
    PRIVATE
        GTest::gtest_main
        network_lib
)

gtest_discover_tests(tests)