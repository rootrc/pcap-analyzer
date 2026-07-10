#pragma once

namespace net::ip {

constexpr uint8_t PROTOCOL_UDP = 17;
constexpr uint8_t PROTOCOL_TCP = 6;
constexpr uint8_t PROTOCOL_ICMP = 1;
constexpr uint8_t PROTOCOL_ICMPV6 = 58;

constexpr const char* protocolName(uint8_t protocol) {
    switch (protocol) {
        case PROTOCOL_TCP: return "TCP";
        case PROTOCOL_UDP: return "UDP";
        case PROTOCOL_ICMP: return "ICMP";
        case PROTOCOL_ICMPV6: return "ICMPV6";
        default: return "?";
    }
}

}