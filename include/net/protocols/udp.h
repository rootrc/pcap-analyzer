#pragma once

#include <net/core/endian.h>
#include <net/core/parse_error.h>
#include <net/protocols/ipv4.h>
#include <net/protocols/ipv6.h>

#include <cstdint>
#include <cstddef>
#include <ostream>
#include <span>

// https://datatracker.ietf.org/doc/html/rfc768

namespace net::udp {

constexpr size_t HEADER_LEN = 8;

#pragma pack(push, 1)
struct Header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};
#pragma pack(pop)
static_assert(sizeof(Header) == HEADER_LEN);

ParseError parse(std::span<const uint8_t>& span, Header& header, const ip::v4::Header& ip_header, Endian endian);
ParseError parse(std::span<const uint8_t>& span, Header& header, const ip::v6::Header& ip_header, Endian endian);

std::ostream& operator<<(std::ostream& os, const Header& h);

}

