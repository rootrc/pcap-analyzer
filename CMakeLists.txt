cmake_minimum_required(VERSION 3.16)

project(PcapAnalyzer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(network_lib
    src/net/capture/pcap.cpp
    src/net/capture/pcap_reader.cpp
    src/net/core/checksum.cpp
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

if(BUILD_TESTING)
    enable_testing()

    find_package(GTest REQUIRED)
    include(GoogleTest)

    set(TEST_MAIN tests/test_main.cpp)

    add_library(test_lib
        tests/testgen/protocol_generator.cpp
    )

    target_include_directories(test_lib
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )

    target_link_libraries(test_lib
        PUBLIC
            network_lib
    )

    set(CAPTURE_TESTS
        pcap_file_header
        pcap_packet_header
    )

    foreach(test IN LISTS CAPTURE_TESTS)
        add_executable(${test}_tests
            ${TEST_MAIN}
            tests/captures/${test}_tests.cpp
        )

        target_link_libraries(${test}_tests
            PRIVATE
                # network_lib
                test_lib
                GTest::gtest
        )

        target_include_directories(${test}_tests
            PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/tests
        )

        gtest_discover_tests(${test}_tests)
    endforeach()

    set(PROTOCOL_TESTS
        ethernet
        ipv4
        ipv6
        tcp
        udp
    )

    foreach(test IN LISTS PROTOCOL_TESTS)
        add_executable(${test}_tests
            ${TEST_MAIN}
            tests/protocols/${test}_tests.cpp
        )

        target_link_libraries(${test}_tests
            PRIVATE
                # network_lib
                test_lib
                GTest::gtest
        )

        target_include_directories(${test}_tests
            PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/tests
        )

        gtest_discover_tests(${test}_tests)
    endforeach()
endif()