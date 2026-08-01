#include <gtest/gtest.h>
#include <net/capture/pcap.h>
#include <net/decode/pkt_decoder.h>
#include "../common/header_tester.h"
#include "../testgen/packet_generator.h"

net::ParseError decodePcapPacket(std::span<const uint8_t>& span, net::Packet& out) {
    span = span.subspan(net::pcap::PACKET_HEADER_LEN);
    out.setDatatypeFromLinktype(net::pcap::LINKTYPE_ETHERNET);
    return net::decode::decodePacket(span, out);
}

auto parsePcapPacket = test::bindHeaderParser<
    decltype(decodePcapPacket),
    net::Packet
>(
    decodePcapPacket
);

RANDOMIZED_TEST(PCAP_PACKET, Randomized, g_randomizedIterations, [](uint8_t* data) {testgen::makePcapPacket(data, 1024);}, parsePcapPacket)