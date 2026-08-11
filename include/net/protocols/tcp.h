#pragma once

#include <net/util/endian.h>
#include <net/util/parse_error.h>
#include <net/protocols/ipv4.h>
#include <net/protocols/ipv6.h>

#include <span>
#include <string>

// https://datatracker.ietf.org/doc/html/rfc768

namespace net::tcp {

constexpr size_t MIN_DATA_OFFSET = 5;
constexpr size_t MAX_DATA_OFFSET = 15;
constexpr size_t MIN_HEADER_LEN = sizeof(uint32_t) * MIN_DATA_OFFSET;
constexpr size_t MAX_HEADER_LEN = sizeof(uint32_t) * MAX_DATA_OFFSET;

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
    constexpr size_t header_length() const noexcept { return sizeof(uint32_t) * data_offset(); }
    constexpr bool cwr() const noexcept { return flags & 0x80; }
    constexpr bool ece() const noexcept { return flags & 0x40; }
    constexpr bool urg() const noexcept { return flags & 0x20; }
    constexpr bool ack() const noexcept { return flags & 0x10; }
    constexpr bool psh() const noexcept { return flags & 0x08; }
    constexpr bool rst() const noexcept { return flags & 0x04; }
    constexpr bool syn() const noexcept { return flags & 0x02; }
    constexpr bool fin() const noexcept { return flags & 0x01; }

    std::string toString() const noexcept;
};
#pragma pack(pop)
static_assert(sizeof(Header) == MIN_HEADER_LEN);

ParseError parse(std::span<const uint8_t>& span, Header& header, const ip::v4::Header& ip_header, Endian endian);
ParseError parse(std::span<const uint8_t>& span, Header& header, const ip::v6::Header& ip_header, Endian endian);

std::ostream& operator<<(std::ostream& os, const Header& h);

}