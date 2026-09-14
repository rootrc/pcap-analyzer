#include <net/capture/pcap.h>

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::vector<uint8_t> buf(data, data + size);
    std::span<const uint8_t> span{buf};

    net::pcap::FileHeader file_header{};
    net::Endian endian = net::Endian::Little;
    if (net::pcap::parse(span, file_header, endian) != net::ParseError::None) return 0;
    (void)file_header.toString();
    (void)file_header.toJson();

    net::pcap::PacketHeader packet_header{};
    while (net::pcap::parse(span, packet_header, endian) == net::ParseError::None) {
        (void)packet_header.toString();
        (void)packet_header.toJson();
        if (span.size() < packet_header.incl_len) break;
        span = span.subspan(packet_header.incl_len);
    }
    return 0;
}
