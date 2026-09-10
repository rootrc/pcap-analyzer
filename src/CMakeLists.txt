add_library(network_lib
    net/analysis/benchmark.cpp
    net/analysis/dns_table.cpp
    net/analysis/stats_engine.cpp
    net/capture/pcap.cpp
    net/capture/pcap_reader.cpp
    net/decode/app_decoder.cpp
    net/decode/decoder.cpp
    net/decode/packet.cpp
    net/decode/packet_decoder.cpp
    net/flow/flow_key.cpp
    net/flow/flow_table.cpp
    net/flow/tcp_reassembler.cpp
    net/protocols/ethernet.cpp
    net/protocols/vlan.cpp
    net/protocols/ipv4.cpp
    net/protocols/ipv6.cpp
    net/protocols/arp.cpp
    net/protocols/tcp.cpp
    net/protocols/udp.cpp
    net/protocols/icmp.cpp
    net/protocols/icmpv6.cpp
    net/protocols/dns.cpp
    net/protocols/http.cpp
    net/util/checksum.cpp
    net/util/text.cpp
)

target_include_directories(network_lib
    PUBLIC
        ${PCAP_ANALYZER_INCLUDE_DIR}
)

add_executable(analyzer
    cli/main.cpp
    cli/cli.cpp
)

set_target_properties(analyzer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

target_link_libraries(analyzer
    PRIVATE
        network_lib
)
