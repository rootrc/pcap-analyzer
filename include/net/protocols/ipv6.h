#pragma once

#include <net/core/endian.h>
#include <net/core/parse_error.h>

#include <cstdint>
#include <cstddef>
#include <ostream>
#include <span>

// https://datatracker.ietf.org/doc/html/rfc8200

namespace net::ip::v6 {

constexpr size_t HEADER_LEN = 40;

#pragma pack(push, 1)
struct Header {
    uint32_t version_tc_fl;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src_ip[16];
    uint8_t dst_ip[16];
};
#pragma pack(pop)
static_assert(sizeof(Header) == HEADER_LEN);

ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian);
uint64_t computePseudoHeaderSum(const Header& ip_header);

std::ostream& operator<<(std::ostream& os, const Header& h);

}