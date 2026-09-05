#include <net/util/checksum.h>
#include <net/util/endian.h>

#include <cstring>

// The one's-complement sum is order-independent, so 16-bit words can be
// accumulated in host (little-endian) order and byte-swapped once after the
// final fold, instead of byte-swapping every word inside the loop. Four
// independent accumulators keep the add latency chain off the critical path.
bool net::verifyChecksum(const uint8_t* data, size_t len, uint64_t pseudo_header_sum) {
    uint64_t a = 0, b = 0, c = 0, d = 0;
    size_t i = 0;

    for (; i + 32 <= len; i += 32) {
        uint64_t w0, w1, w2, w3;
        std::memcpy(&w0, data + i, 8);
        std::memcpy(&w1, data + i + 8, 8);
        std::memcpy(&w2, data + i + 16, 8);
        std::memcpy(&w3, data + i + 24, 8);
        a += (w0 & 0xFFFFFFFF) + (w0 >> 32);
        b += (w1 & 0xFFFFFFFF) + (w1 >> 32);
        c += (w2 & 0xFFFFFFFF) + (w2 >> 32);
        d += (w3 & 0xFFFFFFFF) + (w3 >> 32);
    }
    uint64_t swapped = a + b + c + d;
    for (; i + 4 <= len; i += 4) {
        uint32_t w;
        std::memcpy(&w, data + i, 4);
        swapped += w;
    }
    while (swapped >> 16) swapped = (swapped & 0xFFFF) + (swapped >> 16);

    uint64_t sum = pseudo_header_sum + bswap16(static_cast<uint16_t>(swapped));
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
