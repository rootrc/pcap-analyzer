#include <net/util/checksum.h>
#include <net/util/endian.h>

#include <cstring>

bool net::verifyChecksum(const uint8_t* data, size_t len, uint64_t pseudo_header_sum) {
    uint64_t sum = pseudo_header_sum;
    size_t i = 0;

    for (; i + 8 <= len; i += 8) {
        uint32_t hi, lo;
        std::memcpy(&hi, data + i, 4);
        std::memcpy(&lo, data + i + 4, 4);
        sum += bswap32(hi);
        sum += bswap32(lo);
    }
    for (; i + 2 <= len; i += 2) {
        sum += (static_cast<uint32_t>(data[i]) << 8) | data[i + 1];
    }
    if (i < len) {
        sum += static_cast<uint32_t>(data[i]) << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum) == 0;
}