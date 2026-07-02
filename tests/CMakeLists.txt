find_package(GTest REQUIRED)
include(GoogleTest)

set(TEST_MAIN test_main.cpp)

add_library(test_lib
    testgen/packet_generator.cpp
    testgen/protocol_generator.cpp
)

target_include_directories(test_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(test_lib
    PUBLIC
        network_lib
)

set(RANDOMIZED_ITERATIONS 100 CACHE STRING "Number of randomized test iterations")

set(CAPTURE_TESTS
    packet
    pcap_file_header
    pcap_packet_header
)

foreach(test IN LISTS CAPTURE_TESTS)
    add_executable(${test}_tests
        ${TEST_MAIN}
        capture/${test}_tests.cpp
    )

    target_link_libraries(${test}_tests
        PRIVATE
            test_lib
            GTest::gtest
    )

    target_include_directories(${test}_tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
    )

    gtest_discover_tests(
        ${test}_tests
        EXTRA_ARGS -n ${RANDOMIZED_ITERATIONS}
    )
endforeach()

set(PROTOCOL_TESTS
    ethernet
    vlan
    ipv4
    ipv6
    arp
    tcp
    udp
    icmp
    icmpv6
)

foreach(test IN LISTS PROTOCOL_TESTS)
    add_executable(${test}_tests
        ${TEST_MAIN}
        protocols/${test}_tests.cpp
    )

    target_link_libraries(${test}_tests
        PRIVATE
            test_lib
            GTest::gtest
    )

    target_include_directories(${test}_tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
    )

    gtest_discover_tests(
        ${test}_tests
        EXTRA_ARGS -n ${RANDOMIZED_ITERATIONS}
    )
endforeach()
