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

namespace net::tcp {

constexpr size_t MIN_DATA_OFFSET = 5;
constexpr size_t MAX_DATA_OFFSET = 15;
constexpr size_t MIN_HEADER_LEN = 4 * MIN_DATA_OFFSET;
constexpr size_t MAX_HEADER_LEN = 4 * MAX_DATA_OFFSET;

#pragma pack(push, 1)
struct Header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;

    constexpr uint8_t data_offset() const noexcept { return data_offset_reserved >> 4; }
};
#pragma pack(pop)
static_assert(sizeof(Header) == MIN_HEADER_LEN);

ParseError parse(std::span<const uint8_t>& span, Header& header, const ip::v4::Header& ip_header, Endian endian);
ParseError parse(std::span<const uint8_t>& span, Header& header, const ip::v6::Header& ip_header, Endian endian);

std::ostream& operator<<(std::ostream& os, const Header& h);

}