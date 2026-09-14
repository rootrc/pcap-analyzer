#include <net/protocols/dns.h>

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::vector<uint8_t> buf(data, data + size);
    std::span<const uint8_t> span{buf};
    net::dns::Header header{};
    if (net::dns::parse(span, header, net::Endian::Big) == net::ParseError::None) {
        (void)header.toString();
        (void)header.toJson();
    }
    return 0;
}
