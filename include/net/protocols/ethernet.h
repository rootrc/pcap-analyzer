#pragma once

#include <net/util/endian.h>
#include <net/util/parse_error.h>

#include <span>
#include <string>

// https://www.ieee802.org/3/

namespace net::ethernet {

constexpr size_t HEADER_LEN = 14;

constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
constexpr uint16_t ETHERTYPE_ARP = 0x0806;
constexpr uint16_t ETHERTYPE_VLAN = 0x8100;
constexpr uint16_t ETHERTYPE_VLAN_QQ = 0x88A8;

#pragma pack(push, 1)
struct Header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;

    std::string toString() const noexcept;
};
#pragma pack(pop)
static_assert(sizeof(Header) == HEADER_LEN);

ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian);

std::ostream& printMac(std::ostream& os, const uint8_t mac[6]);
std::ostream& operator<<(std::ostream& os, const Header& h);

constexpr const char* ethertypeName(uint16_t ethertype) {
    switch (ethertype) {
        case ETHERTYPE_IPV4: return "IPv4";
        case ETHERTYPE_IPV6: return "IPv6";
        case ETHERTYPE_ARP: return "ARP";
        case ETHERTYPE_VLAN: return "VLAN";
        case ETHERTYPE_VLAN_QQ: return "VLAN QoS";
        default: return "?";
    }
}

}