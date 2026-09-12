#include <gtest/gtest.h>
#include <net/protocols/ipv6_ext.h>
#include "common/header_tester.h"
#include "testgen/protocol_generator.h"

#include <functional>

namespace {
    inline constexpr uint8_t ext_endof[] = {
        0x06, 0x00,
        0x01, 0x04, 0x00, 0x00,
    };
    inline constexpr uint8_t ext_length[] = {
        0x06, 0x01,
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00,
    };
    inline constexpr uint8_t ah_short[] = {
        0x06, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x01, 0x00,
    };
    inline constexpr uint8_t routing_odd_len[] = {
        0x06, 0x03,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
}

auto parseIpv6Ext(uint8_t type) {
    return test::bindHeaderParser<
        decltype(net::ip::v6::ext::parse),
        net::ip::v6::ext::Header
    >(
        net::ip::v6::ext::parse,
        type,
        net::Endian::Big
    );
}

TEST(IPV6_EXT, Randomized) {
    uint8_t type = 0;
    auto parseIpv6Ext = test::bindHeaderParser<
        decltype(net::ip::v6::ext::parse),
        net::ip::v6::ext::Header
    >(
        net::ip::v6::ext::parse,
        std::ref(type),
        net::Endian::Big
    );
    test::runRandomizedTest(g_randomizedIterations, [&](uint8_t* data) {
        testgen::makeIPv6ExtHeader(data, net::ip::PROTOCOL_TCP, &type);
    }, parseIpv6Ext);
}

HEADER_TEST(IPV6_EXT, UnexpectedEndofBuffer, ext_endof, net::ParseError::UnexpectedEof, parseIpv6Ext(net::ip::PROTOCOL_IPV6_OPTS))
HEADER_TEST(IPV6_EXT, UnexpectedHeaderLength, ext_length, net::ParseError::UnexpectedEof, parseIpv6Ext(net::ip::PROTOCOL_IPV6_OPTS))
HEADER_TEST(IPV6_EXT, RejectsShortAh, ah_short, net::ParseError::MalformedHeader, parseIpv6Ext(net::ip::PROTOCOL_AH))
HEADER_TEST(IPV6_EXT, RejectsOddRoutingLength, routing_odd_len, net::ParseError::MalformedHeader, parseIpv6Ext(net::ip::PROTOCOL_IPV6_ROUTE))
