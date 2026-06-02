#pragma once

#include <net/core/buffer_view.h>
#include <net/core/endian.h>

#include <cstdint>
#include <cstddef>
#include <ostream>

// https://datatracker.ietf.org/doc/html/rfc791

namespace net::ip::v4 {
    constexpr size_t MIN_HEADER_LEN = 20;
    constexpr size_t MAX_HEADER_LEN = 60;

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
    };
    #pragma pack(pop)
    static_assert(sizeof(Header) == MIN_HEADER_LEN);

    size_t parse(BufferView& buf, Header& header, Endian endian);
    uint64_t computePseudoHeaderSum(const Header& ip_header);

    std::ostream& operator<<(std::ostream& os, const Header& h);
}