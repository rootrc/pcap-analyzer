#pragma once

#include <net/util/text.h>

#include <cstdint>
#include <string_view>

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