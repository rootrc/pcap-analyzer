cmake_minimum_required(VERSION 3.16)

project(PcapAnalyzer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)

set(PCAP_SANITIZE "" CACHE STRING "Comma-separated sanitizers for every target, e.g. address,undefined (GCC/Clang only)")

if(PCAP_SANITIZE)
    if(MSVC)
        message(FATAL_ERROR "PCAP_SANITIZE is only supported with GCC or Clang")
    endif()
    add_compile_options(-fsanitize=${PCAP_SANITIZE} -fno-sanitize-recover=all -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=${PCAP_SANITIZE})
endif()

set(PCAP_ANALYZER_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_subdirectory(src)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
