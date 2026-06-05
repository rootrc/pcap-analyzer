
#pragma once

#include <net/capture/pcap.h>
#include <net/core/buffer_view.h>
#include <net/protocols/protocols.h>

#include "vector"

#pragma once

namespace net::pcap {
    struct Packet {
        enum class NetworkType { None, IPv4, IPv6 };

        enum class TransportType { None, TCP, UDP };

        PacketHeader record{};
    
        ethernet::Header eth{};
    
        NetworkType network = NetworkType::None;
        ip::v4::Header ipv4{};
        ip::v6::Header ipv6{};
    
        TransportType transport = TransportType::None;
        tcp::Header tcp{};
        udp::Header udp{};
    
        std::vector<uint8_t> payload;
    
        std::vector<uint8_t> raw;
    };
}