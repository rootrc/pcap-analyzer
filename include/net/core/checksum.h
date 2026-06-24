#pragma once

#include <cstdint>
#include <cstddef>

namespace net {

bool verifyChecksum(const uint8_t* data, size_t len, uint64_t pseudo_header_sum = 0);

}