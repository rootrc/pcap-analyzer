cmake_minimum_required(VERSION 3.16)

project(PcapAnalyzer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)

set(PCAP_ANALYZER_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_subdirectory(include)
add_subdirectory(src)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
