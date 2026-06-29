#pragma once

#include <net/core/endian.h>
#include <net/core/parse_error.h>
#include <net/protocols/ipv6.h>

#include <cstdint>
#include <cstddef>
#include <ostream>
#include <span>

// https://datatracker.ietf.org/doc/html/rfc4443

namespace net::icmpv6 {
    constexpr size_t HEADER_LEN = 8;
    
    constexpr uint32_t MIN_MTU = 1280;
    
    constexpr uint8_t TYPE_UNREACHABLE = 1;
    constexpr uint8_t TYPE_PACKET_TOO_BIG = 2;
    constexpr uint8_t TYPE_TTL_EXCEEDED = 3;
    constexpr uint8_t TYPE_PARAM_PROBLEM = 4;
    constexpr uint8_t TYPE_ECHO_REQUEST = 128;
    constexpr uint8_t TYPE_ECHO_REPLY = 129;
    constexpr uint8_t TYPE_ROUTER_SOLICIT = 133;
    constexpr uint8_t TYPE_ROUTER_ADVERT = 134;
    constexpr uint8_t TYPE_NEIGHBOR_SOLICIT = 135;
    constexpr uint8_t TYPE_NEIGHBOR_ADVERT = 136;

    constexpr uint8_t CODE_UNREACH_NO_ROUTE = 0;
    constexpr uint8_t CODE_UNREACH_ADMIN = 1;
    constexpr uint8_t CODE_UNREACH_BEYOND_SCOPE = 2;
    constexpr uint8_t CODE_UNREACH_ADDR = 3;
    constexpr uint8_t CODE_UNREACH_PORT = 4;

    constexpr uint8_t CODE_TTL_IN_TRANSIT = 0;
    constexpr uint8_t CODE_TTL_REASSEMBLY = 1;

    constexpr uint8_t CODE_PARAM_BAD_HEADER = 0;
    constexpr uint8_t CODE_PARAM_UNKNOWN_NEXT = 1;
    constexpr uint8_t CODE_PARAM_UNKNOWN_OPTION = 2;

    #pragma pack(push, 1)
    struct Header {
        uint8_t type;
        uint8_t code;
        uint16_t checksum;
        union {
            struct { uint16_t id; uint16_t seq; } echo;  // type 128/129
            uint32_t mtu; // type 2
            uint32_t pointer; // type 4
        }; // 133/134/135/136 unsupported
    };
    #pragma pack(pop)
    static_assert(sizeof(Header) == HEADER_LEN);

    ParseError parse(std::span<const uint8_t>& span, Header& header, const ip::v6::Header& ip_header, Endian endian);

    std::ostream& operator<<(std::ostream& os, const Header& h);
}