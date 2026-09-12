find_package(GTest QUIET)

if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.zip
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

include(GoogleTest)

set(TEST_MAIN test_main.cpp)

add_library(test_lib
    testgen/protocol_generator.cpp
    testgen/packet_generator.cpp
    testgen/pcap_generator.cpp
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

# Each module gets its own gtest binary: <dir>/<name>_tests.cpp -> <name>_tests
function(add_module_tests dir)
    foreach(test IN LISTS ARGN)
        add_executable(${test}_tests
            ${TEST_MAIN}
            ${dir}/${test}_tests.cpp
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
endfunction()

set(CAPTURE_TESTS
    pcap_file_header
    pcap_packet_header
    pcap_reader
)

set(DECODE_TESTS
    packet_decoder
)

set(PROTOCOL_TESTS
    ethernet
    vlan
    ipv4
    ipv6
    ipv6_ext
    arp
    tcp
    udp
    icmp
    icmpv6
    dns
    http
)

add_module_tests(capture ${CAPTURE_TESTS})
add_module_tests(decode ${DECODE_TESTS})
add_module_tests(protocols ${PROTOCOL_TESTS})
