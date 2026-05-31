cmake_minimum_required(VERSION 3.16)

project(PcapAnalyzer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(analyzer
    src/main.cpp
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
)

gtest_discover_tests(tests)