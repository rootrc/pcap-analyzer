#pragma once

#include <net/protocols/ip.h>
#include <net/protocols/ipv6.h>
#include <net/util/endian.h>
#include <net/util/parse_error.h>

#include <span>
#include <string>

// https://datatracker.ietf.org/doc/html/rfc8200
// https://datatracker.ietf.org/doc/html/rfc4302
// https://datatracker.ietf.org/doc/html/rfc8754

namespace net::ip::v6::ext {

constexpr size_t MIN_HEADER_LEN = 8;
constexpr size_t AH_MIN_LEN = 12;

constexpr size_t MAX_HEADERS = 8;

constexpr uint8_t ROUTING_TYPE_0 = 0;
constexpr uint8_t ROUTING_TYPE_2 = 2;
constexpr uint8_t ROUTING_TYPE_SRH = 4;

constexpr size_t ROUTING_ADDRESS_OFFSET = 8;

constexpr bool isExtension(uint8_t next_header) {
    switch (next_header) {
        case PROTOCOL_HOPOPT:
        case PROTOCOL_IPV6_ROUTE:
        case PROTOCOL_IPV6_FRAG:
        case PROTOCOL_AH:
        case PROTOCOL_IPV6_OPTS:
        case PROTOCOL_MOBILITY:
        case PROTOCOL_HIP:
        case PROTOCOL_SHIM6:
            return true;
        default:
            return false;
    }
}

#pragma pack(push, 1)
struct WireHeader {
    uint8_t next_header;
    uint8_t hdr_ext_len;
    union {
        struct { uint8_t routing_type; uint8_t segments_left; uint32_t reserved; } routing; // 43
        struct { uint16_t offset_flags; uint32_t identification; } fragment; // 44
        struct { uint16_t reserved; uint32_t spi; } ah; // 51
        uint8_t data[6]; // options (0, 60) and everything else
    };
};
#pragma pack(pop)
static_assert(sizeof(WireHeader) == MIN_HEADER_LEN);

struct Header {
    uint8_t type;
    uint8_t next_header;
    uint16_t length;

    uint8_t routing_type;
    uint8_t segments_left;
    bool has_final_dst;
    uint8_t final_dst[16];

    uint16_t fragment_offset;
    bool more_fragments;
    uint32_t identification;

    uint32_t spi;

    constexpr bool isFragment() const noexcept { return type == PROTOCOL_IPV6_FRAG && (fragment_offset != 0 || more_fragments); }
    constexpr bool isAtomicFragment() const noexcept { return type == PROTOCOL_IPV6_FRAG && fragment_offset == 0 && !more_fragments; }

    std::string toString() const noexcept;
    std::string toJson() const noexcept;
};

ParseError parse(std::span<const uint8_t>& span, Header& header, uint8_t type, Endian endian);

ip::v6::Header pseudoHeader(const ip::v6::Header& ip_header, std::span<const Header> exts, size_t upper_len) noexcept;

std::ostream& operator<<(std::ostream& os, const Header& h);

}
