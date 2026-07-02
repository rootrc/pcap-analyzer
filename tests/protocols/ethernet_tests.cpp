#include <gtest/gtest.h>
#include <net/core/parse_error.h>
#include <net/core/endian.h>
#include <net/protocols/ethernet.h>
#include "../common/header_tester.h"
#include "../testgen/protocol_generator.h"

namespace {    
    inline constexpr uint8_t ethernet_endof[] = {
        0xF4, 0x5C, 0x89, 0xA1, 0xB2, 0xC3,
        0x3C, 0x52, 0x82, 0x11, 0x22, 0x33,
        0x08,
    };
}

auto parseEthernet = test::bindHeaderParser<
    decltype(net::ethernet::parse),
    net::ethernet::Header
>(
    net::ethernet::parse,
    net::Endian::Big
);

RANDOMIZED_TEST(ETHERNET, Randomized, g_randomizedIterations, [](uint8_t* data) {testgen::makeEthernetHeader(data, 0);}, parseEthernet)
HEADER_TEST(ETHERNET, UnexpectedEndofBuffer, ethernet_endof, net::ParseError::UnexpectedEof, parseEthernet)