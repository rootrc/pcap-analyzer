#include <gtest/gtest.h>
#include <net/core/parse_error.h>
#include <net/core/endian.h>
#include <net/capture/pcap.h>
#include "../common/header_tester.h"
#include "../testgen/packet_generator.h"

namespace {
    inline constexpr uint8_t file_header_endof[] = {
        0xD4, 0xC3, 0xB2, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0xFF, 0xFF, 0xFF,
        0x01, 0x00, 0x00,
    };
    inline constexpr uint8_t file_header_version[] = {
        0x4d, 0x3c, 0xb2, 0xa1,
        0x02, 0x00,
        0x03, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xAF, 0xFF, 0xFF, 0xFF,
        0x01, 0x00, 0x00, 0x00,
    };
    inline constexpr uint8_t file_header_field_magic[] = {
        0xD4, 0xC3, 0xB2, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0xFF, 0xFF, 0xFF,
        0x01, 0x00, 0x00, 0x00,
    };
    inline constexpr uint8_t file_header_field[] = {
        0xa1, 0xb2, 0x3c, 0x4d,
        0x00, 0x02,
        0x00, 0x04,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    };
    inline constexpr uint8_t file_header_linktype[] = {
        0xa1, 0xb2, 0xc3, 0xd4,
        0x00, 0x02,
        0x00, 0x04,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x12, 0x34, 0x56, 0x78,
        0x00, 0x00, 0x00, 0x65,
    };
}

using ParseFn = net::ParseError (*)(std::span<const uint8_t>&, net::pcap::FileHeader&, net::Endian&);
auto parsePcapFileHeader = test::bindHeaderParser<
    ParseFn,
    net::pcap::FileHeader
>(
    static_cast<ParseFn>(net::pcap::parse),
    net::Endian::Little
);

RANDOMIZED_TEST(PCAP_FILE, Randomized, 100, [](uint8_t* data) {testgen::makePcapFileHeader(data); }, parsePcapFileHeader)
HEADER_TEST(PCAP_FILE, UnexpectedEndofBuffer, file_header_endof, net::ParseError::UnexpectedEof, parsePcapFileHeader)
HEADER_TEST(PCAP_FILE, RejectsUnsupportedVersion, file_header_version, net::ParseError::UnsupportedVersion, parsePcapFileHeader)
HEADER_TEST(PCAP_FILE, RejectsInvalidFieldValue0, file_header_field_magic, net::ParseError::InvalidFieldValue, parsePcapFileHeader)
HEADER_TEST(PCAP_FILE, RejectsInvalidFieldValue1, file_header_field, net::ParseError::InvalidFieldValue, parsePcapFileHeader)
HEADER_TEST(PCAP_FILE, RejectsUnsupportedLinktype, file_header_linktype, net::ParseError::UnsupportedLinktype, parsePcapFileHeader)