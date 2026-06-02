#pragma once

#include <net/core/endian.h>
#include <net/core/buffer_view.h>

#include <cstdint>
#include <cstddef>
#include <ostream>

// https://www.ieee802.org/3/

namespace net::ethernet {
    constexpr size_t HEADER_LEN = 14;

    constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
    constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;

    #pragma pack(push, 1)
    struct Header {
        uint8_t dst_mac[6];
        uint8_t src_mac[6];
        uint16_t ethertype;
    };
    #pragma pack(pop)
    static_assert(sizeof(Header) == HEADER_LEN);

    size_t parse(BufferView& buf, Header& header, Endian endian);

    std::ostream& operator<<(std::ostream& os, const Header& h);
}