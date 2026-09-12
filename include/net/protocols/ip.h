#pragma once

#include <net/util/text.h>

#include <cstdint>
#include <string_view>

namespace net::ip {

constexpr uint8_t PROTOCOL_UDP = 17;
constexpr uint8_t PROTOCOL_TCP = 6;
constexpr uint8_t PROTOCOL_ICMP = 1;
constexpr uint8_t PROTOCOL_ICMPV6 = 58;

// IPv6 extension headers
constexpr uint8_t PROTOCOL_HOPOPT = 0;
constexpr uint8_t PROTOCOL_IPV6_ROUTE = 43;
constexpr uint8_t PROTOCOL_IPV6_FRAG = 44;
constexpr uint8_t PROTOCOL_ESP = 50;
constexpr uint8_t PROTOCOL_AH = 51;
constexpr uint8_t PROTOCOL_IPV6_NONXT = 59;
constexpr uint8_t PROTOCOL_IPV6_OPTS = 60;
constexpr uint8_t PROTOCOL_MOBILITY = 135;
constexpr uint8_t PROTOCOL_HIP = 139;
constexpr uint8_t PROTOCOL_SHIM6 = 140;

constexpr const char* protocolName(uint8_t protocol) {
    switch (protocol) {
        case PROTOCOL_TCP: return "TCP";
        case PROTOCOL_UDP: return "UDP";
        case PROTOCOL_ICMP: return "ICMP";
        case PROTOCOL_ICMPV6: return "ICMPV6";
        case PROTOCOL_HOPOPT: return "HOPOPT";
        case PROTOCOL_IPV6_ROUTE: return "IPv6-Route";
        case PROTOCOL_IPV6_FRAG: return "IPv6-Frag";
        case PROTOCOL_ESP: return "ESP";
        case PROTOCOL_AH: return "AH";
        case PROTOCOL_IPV6_NONXT: return "IPv6-NoNxt";
        case PROTOCOL_IPV6_OPTS: return "IPv6-Opts";
        case PROTOCOL_MOBILITY: return "Mobility";
        case PROTOCOL_HIP: return "HIP";
        case PROTOCOL_SHIM6: return "Shim6";
        default: return "?";
    }
}

inline bool protocolFromName(std::string_view name, uint8_t& out) noexcept {
    if (util::isEquals(name, "tcp")) { out = PROTOCOL_TCP; return true; }
    if (util::isEquals(name, "udp")) { out = PROTOCOL_UDP; return true; }
    if (util::isEquals(name, "icmp")) { out = PROTOCOL_ICMP; return true; }
    if (util::isEquals(name, "icmpv6")) { out = PROTOCOL_ICMPV6; return true; }
    uint64_t value = 0;
    if (!util::parseUint(name, value, 255)) return false;
    out = static_cast<uint8_t>(value);
    return true;
}

}