set(FUZZ_TARGETS
    fuzz_packet
    fuzz_dns
    fuzz_http
    fuzz_pcap_header
    fuzz_capture
    fuzz_address
)

function(add_fuzz_target name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE network_lib)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
    set_target_properties(${name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/fuzz")
endfunction()

add_executable(fuzz_seeds fuzz_seeds.cpp)
target_link_libraries(fuzz_seeds PRIVATE network_lib)
target_compile_definitions(fuzz_seeds PRIVATE PCAP_ANALYZER_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

if(BUILD_FUZZERS)
    foreach(target IN LISTS FUZZ_TARGETS)
        add_fuzz_target(${target})
    endforeach()
endif()
