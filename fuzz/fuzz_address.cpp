#include <net/protocols/ipv4.h>
#include <net/protocols/ipv6.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <string_view>

namespace {

void roundTripV4(const uint8_t addr[4]) {
    std::ostringstream oss;
    net::ip::v4::printIp(oss, addr);
    uint8_t parsed[4] = {};
    if (!net::ip::v4::addressFromString(oss.str(), parsed) || std::memcmp(addr, parsed, 4) != 0) {
        std::fprintf(stderr, "IPv4 round trip failed for \"%s\"\n", oss.str().c_str());
        std::abort();
    }
}

void roundTripV6(const uint8_t addr[16]) {
    std::ostringstream oss;
    net::ip::v6::printIp(oss, addr);
    uint8_t parsed[16] = {};
    if (!net::ip::v6::addressFromString(oss.str(), parsed) || std::memcmp(addr, parsed, 16) != 0) {
        std::fprintf(stderr, "IPv6 round trip failed for \"%s\"\n", oss.str().c_str());
        std::abort();
    }
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size >= 4) {
        uint8_t v4[4];
        std::memcpy(v4, data, 4);
        roundTripV4(v4);
    }
    if (size >= 16) {
        uint8_t v6[16];
        std::memcpy(v6, data, 16);
        roundTripV6(v6);
    }

    std::string text(reinterpret_cast<const char*>(data), size);
    uint8_t v4[4];
    if (net::ip::v4::addressFromString(text, v4)) roundTripV4(v4);
    uint8_t v6[16];
    if (net::ip::v6::addressFromString(text, v6)) roundTripV6(v6);
    return 0;
}
