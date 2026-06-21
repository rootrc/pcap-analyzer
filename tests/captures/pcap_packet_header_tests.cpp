#include <gtest/gtest.h>
#include <net/core/parse_error.h>
#include <net/core/endian.h>
#include <net/capture/pcap.h>
#include "../common/header_tester.h"

namespace {   
    inline constexpr uint8_t packet_header_valid[] = {
        0x5E, 0x2A, 0x3C, 0x01,
        0x7B, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x3C, 0x00,
        0x00, 0x00, 0x3C, 0x00,
    };
    inline constexpr uint8_t packet_header_endof[] = {
        0x5E, 0x2A, 0x3C, 0x01,
        0x7B, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x3C, 0x00,
        0x00, 0x00, 0x3C,
    };
    inline constexpr uint8_t packet_header_field[] = {
        0x5E, 0x2A, 0x3C, 0x01,
        0x7B, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x3C, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    inline constexpr uint8_t packet_header_malformed[] = {
        0x00, 0x83, 0xFF, 0x00,
        0x1A, 0x25, 0x24, 0x00,
        0x01, 0x1F, 0x00, 0x00,
        0x00, 0x1F, 0x00, 0x00,
    };
}

using ParseFn = net::ParseError (*)(std::span<const uint8_t>&, net::pcap::PacketHeader&, net::Endian);
auto parsePcapPacketHeader = test::bindHeaderParser<
    ParseFn,
    net::pcap::PacketHeader
>(
    static_cast<ParseFn>(net::pcap::parse),
    net::Endian::Little
);

HEADER_TEST(PCAP_PACKET, ParsesValid, packet_header_valid, net::ParseError::None, parsePcapPacketHeader)
HEADER_TEST(PCAP_PACKET, UnexpectedEndofBuffer, packet_header_endof, net::ParseError::UnexpectedEof, parsePcapPacketHeader)
HEADER_TEST(PCAP_PACKET, RejectsInvalidFieldValue, packet_header_field, net::ParseError::InvalidFieldValue, parsePcapPacketHeader)
HEADER_TEST(PCAP_PACKET, RejectsMalformedHeader, packet_header_malformed, net::ParseError::MalformedHeader, parsePcapPacketHeader)
