#pragma once

#include <net/core/endian.h>
#include <net/core/parse_error.h>

#include <span>

// https://datatracker.ietf.org/doc/html/rfc8200

namespace net::ip::v6 {

constexpr size_t HEADER_LEN = 40;

constexpr uint16_t SUPPORTED_VERSION = 6;

#pragma pack(push, 1)
struct Header {
    uint32_t version_tc_fl;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src_ip[16];
    uint8_t dst_ip[16];

    constexpr uint8_t version() const noexcept { return version_tc_fl >> 28; }
    constexpr uint8_t tc() const noexcept { return (version_tc_fl >> 20) & 0xFF; }
    constexpr uint32_t fl() const noexcept { return version_tc_fl & 0x000FFFFF; }
};
#pragma pack(pop)
static_assert(sizeof(Header) == HEADER_LEN);

ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian);
uint64_t computePseudoHeaderSum(const Header& ip_header);

std::ostream& printIp(std::ostream& os, const uint8_t ip[16]);
std::ostream& operator<<(std::ostream& os, const Header& h);

}