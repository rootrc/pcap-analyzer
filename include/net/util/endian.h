#pragma once

#include <cstdint>

#if !defined(_MSC_VER) || defined(__clang__)
    static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "This program requires little-endian architecture");
#endif

namespace net {

enum class Endian { Big, Little };

inline uint16_t bswap16(uint16_t x) {
    return (x >> 8) | (x << 8);
}
inline uint32_t bswap32(uint32_t x) {
    return ((x >> 24) & 0x000000FF) |
        ((x >> 8)  & 0x0000FF00) |
        ((x << 8)  & 0x00FF0000) |
        ((x << 24) & 0xFF000000);
}
inline uint16_t toHost16(uint16_t v, Endian e) {
    return e == Endian::Big ? bswap16(v) : v;
}
inline uint32_t toHost32(uint32_t v, Endian e) {
    return e == Endian::Big ? bswap32(v) : v;
}

}