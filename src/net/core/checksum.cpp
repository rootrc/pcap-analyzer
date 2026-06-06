#include <net/core/checksum.h>

bool net::verifyChecksum(const uint8_t* data, size_t len, uint64_t pseudo_header_sum ) {
    uint64_t sum = pseudo_header_sum;

    for (size_t i = 0; i < len; i += 2) {
        if (i + 1 < len) {
            sum += (data[i] << 8) | data[i + 1];
        } else {
            sum += (data[i] << 8);
        }
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum) == 0;
}