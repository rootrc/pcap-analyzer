#pragma once

#include <net/util/endian.h>
#include <net/util/parse_error.h>

#include <span>
#include <string>

// https://wiki.wireshark.org/VLAN

namespace net::vlan {

constexpr size_t HEADER_LEN = 4;

constexpr size_t MAX_TAGS = 4;

constexpr uint16_t VID_RESERVED = 0x0FFF;

#pragma pack(push, 1)
struct Header {
    uint16_t tci;
    uint16_t ethertype;

    constexpr uint8_t pcp() const noexcept { return tci >> 13; }
    constexpr uint8_t dei() const noexcept { return (tci >> 12) & 0x1; }
    constexpr uint16_t vid() const noexcept { return tci & 0x0FFF; }

    std::string toString() const noexcept;
    std::string toJson() const noexcept;
};
#pragma pack(pop)
static_assert(sizeof(Header) == HEADER_LEN);

ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian);

std::ostream& operator<<(std::ostream& os, const Header& h);

}