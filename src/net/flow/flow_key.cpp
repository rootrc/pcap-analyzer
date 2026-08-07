#include <net/flow/flow_key.h>
#include <net/protocols/ip.h>
#include <net/protocols/ipv4.h>
#include <net/protocols/ipv6.h>

#include <iomanip>

namespace net {

bool FlowKey::operator==(const FlowKey& o) const noexcept {
    return memcmp(src_ip, o.src_ip, 16) == 0 &&
            memcmp(dst_ip, o.dst_ip, 16) == 0 &&
            src_port == o.src_port &&
            dst_port == o.dst_port &&
            protocol == o.protocol;
}

bool FlowKey::normalize() noexcept {
    int cmp = memcmp(src_ip, dst_ip, 16);
    if (cmp > 0 || (cmp == 0 && src_port > dst_port)) {
        std::swap(src_port, dst_port);
        uint8_t tmp[16];
        memcpy(tmp, src_ip, 16);
        memcpy(src_ip, dst_ip, 16);
        memcpy(dst_ip, tmp, 16);
        return true;
    }
    return false;
}

size_t FlowKeyHash::operator()(const FlowKey& k) const noexcept {
    size_t h = 14695981039346656037ULL;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&k);
    for (size_t i = 0; i < sizeof(FlowKey); ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

std::ostream& operator<<(std::ostream& os, const FlowKey& key) {
    auto flags = os.flags();
    if (key.isIpv4) {
        ip::v4::printIp(os, key.src_ip);
    } else {
        ip::v6::printIp(os, key.src_ip);
    }
    os << ':' << key.src_port << " -> ";
    if (key.isIpv4) {
        ip::v4::printIp(os, key.dst_ip);
    } else {
        ip::v6::printIp(os, key.dst_ip);
    }
    os << ':' << key.dst_port
       << " (" << ip::protocolName(key.protocol) << ')';
    os.flags(flags);
    return os;
}

}