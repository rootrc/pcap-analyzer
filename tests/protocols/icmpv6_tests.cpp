#include <gtest/gtest.h>
#include <net/core/parse_error.h>
#include <net/core/endian.h>
#include <net/protocols/icmpv6.h>
#include "../common/header_tester.h"
#include "../testgen/protocol_generator.h"

namespace {    
    inline constexpr uint8_t ipv6_pseudo[] = {
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x08,
        0x06,
        0x80,
        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x78,
        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9A, 0xBC,
    };
    inline constexpr uint8_t icmpv6_endof[] = {
        0x01,
        0x00,
        0x00, 0x01,
        0x00, 0x00, 0x00,
    };
    inline constexpr uint8_t icmpv6_invalid_field_type[] = {
        0xFF,
        0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    inline constexpr uint8_t icmpv6_invalid_field_code[] = {
        0x03,
        0x0F,
        0x00, 0x12,
        0x00, 0x00, 0x00, 0x00,
    };
    inline constexpr uint8_t icmpv6_invalid_field_mtu[] = {
        0x02,
        0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    inline constexpr uint8_t icmpv6_checksum[] = {
        0x01,
        0x01,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
}

template <size_t N>
auto parseIcmpv6(const uint8_t (&pseudo_header)[N]) {    
    net::ip::v6::Header header = test::makePseudoHeader<net::ip::v6::Header>(pseudo_header);

    return test::bindHeaderParser<
        decltype(net::icmpv6::parse),
        net::icmpv6::Header
    >(
        net::icmpv6::parse,
        header,
        net::Endian::Big
    );
}

RANDOMIZED_TEST(ICMPV6, Randomized, g_randomizedIterations, [](uint8_t* data) {testgen::makeIcmpv6Header(data, test::makePseudoHeader<net::ip::v6::Header>(ipv6_pseudo));}, parseIcmpv6(ipv6_pseudo))
HEADER_TEST(ICMPV6, UnexpectedEndofBuffer, icmpv6_endof, net::ParseError::UnexpectedEof, parseIcmpv6(ipv6_pseudo))
HEADER_TEST(ICMPV6, RejectsInvalidFieldValueType, icmpv6_invalid_field_type, net::ParseError::InvalidFieldValue, parseIcmpv6(ipv6_pseudo))
HEADER_TEST(ICMPV6, RejectsInvalidFieldValueCode, icmpv6_invalid_field_code, net::ParseError::InvalidFieldValue, parseIcmpv6(ipv6_pseudo))
HEADER_TEST(ICMPV6, RejectsInvalidFieldValueMtu, icmpv6_invalid_field_mtu, net::ParseError::InvalidFieldValue, parseIcmpv6(ipv6_pseudo))
HEADER_TEST(ICMPV6, RejectsChecksumMismatch, icmpv6_checksum, net::ParseError::ChecksumMismatch, parseIcmpv6(ipv6_pseudo))