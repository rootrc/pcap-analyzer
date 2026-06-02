#pragma once

#include <net/core/buffer_view.h>
#include <net/core/endian.h>
#include <net/protocols/ipv4.h>
#include <net/protocols/ipv6.h>

#include <cstdint>
#include <cstddef>
#include <ostream>

// https://datatracker.ietf.org/doc/html/rfc768

namespace net::tcp {
    constexpr size_t MIN_HEADER_LEN = 20;
    constexpr size_t MAX_HEADER_LEN = 60;

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
    };
    #pragma pack(pop)
    static_assert(sizeof(Header) == MIN_HEADER_LEN);

    size_t parse(BufferView& buf, Header& header, const ip::v4::Header& ip_header, Endian endian);
    size_t parse(BufferView& buf, Header& header, const ip::v6::Header& ip_header, Endian endian);

    std::ostream& operator<<(std::ostream& os, const Header& h);
}