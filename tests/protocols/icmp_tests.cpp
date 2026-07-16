#include <gtest/gtest.h>
#include <net/protocols/icmp.h>
#include "../common/header_tester.h"
#include "../testgen/protocol_generator.h"

namespace {    
    inline constexpr uint8_t icmp_endof[] = {
        0x08,
        0x00,
        0x00, 0x08,
        0x00, 0x00, 0x00,
    };
    inline constexpr uint8_t icmp_invalid_field_type[] = {
        0xFF,
        0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    inline constexpr uint8_t icmp_invalid_field_code[] = {
        0x05,
        0x0F,
        0x00, 0x14,
        0x00, 0x00, 0x00, 0x00,
    };
    inline constexpr uint8_t icmp_checksum[] = {
        0x03,
        0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
}

auto parseIcmp = test::bindHeaderParser<
    decltype(net::icmp::parse),
    net::icmp::Header
>(
    net::icmp::parse,
    net::Endian::Big
);

RANDOMIZED_TEST(ICMP, Randomized, g_randomizedIterations, [](uint8_t* data) {testgen::makeIcmpHeader(data);}, parseIcmp)
HEADER_TEST(ICMP, UnexpectedEndofBuffer, icmp_endof, net::ParseError::UnexpectedEof, parseIcmp)
HEADER_TEST(ICMP, RejectsInvalidFieldValueType, icmp_invalid_field_type, net::ParseError::InvalidFieldValue, parseIcmp)
HEADER_TEST(ICMP, RejectsInvalidFieldValueCode, icmp_invalid_field_code, net::ParseError::InvalidFieldValue, parseIcmp)
HEADER_TEST(ICMP, RejectsChecksumMismatch, icmp_checksum, net::ParseError::ChecksumMismatch, parseIcmp)