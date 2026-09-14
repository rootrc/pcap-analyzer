#include <net/capture/pcap.h>
#include <net/decode/packet_decoder.h>

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    bool verify_checksum = data[0] & 1;
    std::vector<uint8_t> buf(data + 1, data + size);

    net::Packet pkt{};
    pkt.setDatatypeFromLinktype(net::pcap::LINKTYPE_ETHERNET);
    std::span<const uint8_t> span{buf};
    if (net::decode::decodePacket(span, pkt, verify_checksum) == net::ParseError::None) {
        (void)pkt.toString();
        (void)pkt.toJson();
    }
    return 0;
}
