#include <gtest/gtest.h>
#include <net/protocols/ipv4.h>
#include "../common/header_tester.h"
#include "../testgen/protocol_generator.h"

namespace {    
    inline constexpr uint8_t ipv4_endof[] = {
        0x45,
        0x00,
        0x00, 0x34,
        0x12, 0x34,
        0x40, 0x00,
        0x40,
        0x06,
        0xA4, 0xDA,
        0xC0, 0xA8, 0x01, 0x64,
        0xC0, 0xA8, 0x01,
    };
    inline constexpr uint8_t ipv4_malformed[] = {
        0x42,
        0x00,
        0x00, 0x34,
        0x12, 0x34,
        0x40, 0x00,
        0x40,
        0x06,
        0xA4, 0xDA,
        0xC0, 0xA8, 0x01, 0x64,
        0xC0, 0xA8, 0x01, 0x01,
    };
    inline constexpr uint8_t ipv4_endof_options[] = {
        0x47,
        0x00,
        0x00, 0x34,
        0x12, 0x34,
        0x40, 0x00,
        0x40,
        0x06,
        0x8A, 0xA4,
        0xAC, 0x10, 0x00, 0x64,
        0xAC, 0x10, 0x00, 0x01,
        0x11, 0x22, 0x33, 0x44,
    };
    inline constexpr uint8_t ipv4_field[] = {
        0x35,
        0x00,
        0x00, 0x34,
        0x12, 0x34,
        0x40, 0x00,
        0x40,
        0x06,
        0xA4, 0xDA,
        0xC0, 0xA8, 0x01, 0x64,
        0xC0, 0xA8, 0x01, 0x01,
    };
    inline constexpr uint8_t ipv4_checksum[] = {
        0x45,
        0x00,
        0x00, 0x34,
        0x12, 0x34,
        0x40, 0x00,
        0x40,
        0x06,
        0xda, 0xa4,
        0xC0, 0xA8, 0x01, 0x64,
        0xC0, 0xA8, 0x01, 0x01,
    };
}

auto parseIpv4 = test::bindHeaderParser<
    decltype(net::ip::v4::parse),
    net::ip::v4::Header
>(
    net::ip::v4::parse,
    net::Endian::Big
);

RANDOMIZED_TEST(IPV4, Randomized, g_randomizedIterations, [](uint8_t* data) {testgen::makeIPv4Header(data, 0, randomgen::randRange8(net::ip::v4::MIN_IHL, net::ip::v4::MAX_IHL));}, parseIpv4)
HEADER_TEST(IPV4, UnexpectedEndofBuffer, ipv4_endof, net::ParseError::UnexpectedEof, parseIpv4)
HEADER_TEST(IPV4, RejectsMalformedHeader, ipv4_malformed, net::ParseError::MalformedHeader, parseIpv4)
HEADER_TEST(IPV4, UnexpectedEndofBufferOptions, ipv4_endof_options, net::ParseError::UnexpectedEof, parseIpv4)
HEADER_TEST(IPV4, RejectsInvalidFieldValue, ipv4_field, net::ParseError::InvalidFieldValue, parseIpv4)
HEADER_TEST(IPV4, RejectsChecksumMismatch, ipv4_checksum, net::ParseError::ChecksumMismatch, parseIpv4)