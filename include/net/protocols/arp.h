#pragma once

#include <net/core/endian.h>
#include <net/core/parse_error.h>

#include <span>

// https://datatracker.ietf.org/doc/html/rfc826

namespace net::arp {
    constexpr size_t MIN_HEADER_LEN = 8;
    constexpr size_t HEADER_STRUCT_LEN = MIN_HEADER_LEN + 4 * sizeof(const uint8_t*);

    constexpr uint16_t HTYPE_ETHERNET = 1;

    constexpr uint16_t OPER_REQUEST = 1;
    constexpr uint16_t OPER_REPLY = 2;

    #pragma pack(push, 1)
    struct Header {
        uint16_t htype;
        uint16_t ptype;
        uint8_t hlen;
        uint8_t plen;
        uint16_t oper;
        const uint8_t* sha;
        const uint8_t* spa;
        const uint8_t* tha;
        const uint8_t* tpa;
    };
    #pragma pack(pop)
    static_assert(sizeof(Header) == HEADER_STRUCT_LEN);

    ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian);

    std::ostream& operator<<(std::ostream& os, const Header& h);
}