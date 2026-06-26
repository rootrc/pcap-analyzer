#pragma once

#include <net/core/endian.h>
#include <net/core/parse_error.h>

#include <cstdint>
#include <cstddef>
#include <ostream>
#include <span>

// https://datatracker.ietf.org/doc/html/rfc791

namespace net::ip::v4 {

constexpr size_t MIN_IHL = 5;
constexpr size_t MAX_IHL = 15;
constexpr size_t MIN_HEADER_LEN = 4 * MIN_IHL;
constexpr size_t MAX_HEADER_LEN = 4 * MAX_IHL;

#pragma pack(push, 1)
struct Header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;

    constexpr uint8_t version() const noexcept { return version_ihl >> 4; }
    constexpr uint8_t ihl() const noexcept { return version_ihl & 0x0F; }
    constexpr uint8_t flags() const noexcept { return flags_fragment >> 13; }
    constexpr uint16_t fragment() const noexcept { return flags_fragment & 0x1FFF; }
};
#pragma pack(pop)
static_assert(sizeof(Header) == MIN_HEADER_LEN);

ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian);
uint64_t computePseudoHeaderSum(const Header& ip_header);

std::ostream& operator<<(std::ostream& os, const Header& h);

}