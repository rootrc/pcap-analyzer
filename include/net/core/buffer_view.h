#pragma once

#include <cstdint>
#include <cstddef>

namespace net {
    struct BufferView {
        const uint8_t* data;
        size_t len;
        size_t pos = 0;

        const uint8_t* current() const {
            return data + pos;
        }

        size_t length() const {
            return len - pos;
        }

        bool advance(size_t n) {
            if (n > length()) return false;
            pos += n;
            return true;
        }
    };
}