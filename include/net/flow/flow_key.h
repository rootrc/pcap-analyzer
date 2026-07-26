#pragma once

#include <cstdint>
#include <cstring>
#include <ostream>

namespace net {

#pragma pack(push, 1)
struct FlowKey {
    bool isIpv4;
    uint8_t src_ip[16];
    uint8_t dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;

    bool operator==(const FlowKey& o) const noexcept;
    bool normalize() noexcept;
};
#pragma pack(pop)

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const noexcept;
};

std::ostream& operator<<(std::ostream& os, const FlowKey& key);

}
