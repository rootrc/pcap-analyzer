#include <net/flow/flow_key.h>
#include <net/protocols/ip.h>
#include <net/protocols/ipv4.h>
#include <net/protocols/ipv6.h>

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace net {

bool FlowKey::operator==(const FlowKey& o) const noexcept {
    return isIpv4 == o.isIpv4 &&
            memcmp(src_ip, o.src_ip, 16) == 0 &&
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

namespace {
bool anyNonZero(const uint8_t* p, size_t n) noexcept {
    return std::any_of(p, p + n, [](uint8_t b) { return b != 0; });
}
}

bool FlowKey::isNonZero() const noexcept {
    return protocol != 0 || src_port != 0 || dst_port != 0 ||
           anyNonZero(src_ip, 16) || anyNonZero(dst_ip, 16);
}

bool FlowKey::matches(const FlowKey& pkt) const noexcept {
    if (protocol != 0 && protocol != pkt.protocol) return false;
    if (src_port != 0 && src_port != pkt.src_port) return false;
    if (dst_port != 0 && dst_port != pkt.dst_port) return false;
    if (anyNonZero(src_ip, 16) && (isIpv4 != pkt.isIpv4 || memcmp(src_ip, pkt.src_ip, 16) != 0)) return false;
    if (anyNonZero(dst_ip, 16) && (isIpv4 != pkt.isIpv4 || memcmp(dst_ip, pkt.dst_ip, 16) != 0)) return false;
    return true;
}

size_t FlowKeyHash::operator()(const FlowKey& k) const noexcept {
    size_t h = 14695981039346656037ULL;
    auto mix = [&h](uint64_t v) noexcept { h ^= v; h *= 1099511628211ULL; };

    if (k.isIpv4) {
        uint32_t src = 0, dst = 0;
        memcpy(&src, k.src_ip, 4);
        memcpy(&dst, k.dst_ip, 4);
        mix((static_cast<uint64_t>(src) << 32) | dst);
    } else {
        uint64_t words[4];
        memcpy(words, k.src_ip, 16);
        memcpy(words + 2, k.dst_ip, 16);
        mix(words[0]); mix(words[1]); mix(words[2]); mix(words[3]);
    }
    mix((static_cast<uint64_t>(k.isIpv4) << 48) |
        (static_cast<uint64_t>(k.src_port) << 32) |
        (static_cast<uint64_t>(k.dst_port) << 16) |
        static_cast<uint64_t>(k.protocol));
    return h;
}

std::string FlowKey::toString() const noexcept {
    std::ostringstream oss;
    if (isIpv4) {
        ip::v4::printIp(oss, src_ip);
    } else {
        oss << '['; ip::v6::printIp(oss, src_ip); oss << ']';
    }
    oss << ':' << std::dec << src_port << " -> ";
    if (isIpv4) {
        ip::v4::printIp(oss, dst_ip);
    } else {
        oss << '['; ip::v6::printIp(oss, dst_ip); oss << ']';
    }
    oss << ':' << std::dec << dst_port
        << " (" << ip::protocolName(protocol) << ')';
    return oss.str();
}

std::string FlowKey::toJson() const noexcept {
    std::ostringstream oss;
    auto flags = oss.flags();
    oss << "\"flow_key\": {\n"
        << "  \"src_ip\": \"";
    if (isIpv4) {
        ip::v4::printIp(oss, src_ip);
    } else {
        ip::v6::printIp(oss, src_ip);
    }
    oss << "\",\n"
        << "  \"dst_ip\": \"";
    if (isIpv4) {
        ip::v4::printIp(oss, dst_ip);
    } else {
        ip::v6::printIp(oss, dst_ip);
    }
    oss.flags(flags);
    oss << "\",\n"
        << "  \"src_port\": " << src_port << ",\n"
        << "  \"dst_port\": " << dst_port << ",\n"
        << "  \"protocol\": \"" << ip::protocolName(protocol) << "\"\n"
        << "}";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const FlowKey& key) {
    return os << key.toString();
}

}