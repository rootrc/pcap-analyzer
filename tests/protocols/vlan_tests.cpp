#include <gtest/gtest.h>
#include <net/core/parse_error.h>
#include <net/core/endian.h>
#include <net/protocols/vlan.h>
#include "../common/header_tester.h"
#include "../testgen/protocol_generator.h"

namespace {    
    inline constexpr uint8_t vlan_endof[] = {
        0x00, 0x64,
        0x08,
    };
}

auto parseVlan = test::bindHeaderParser<
    decltype(net::vlan::parse),
    net::vlan::Header
>(
    net::vlan::parse,
    net::Endian::Big
);

RANDOMIZED_TEST(VLAN, Randomized, 100, [](uint8_t* data) {testgen::makeVlanHeader(data, 0);}, parseVlan)
HEADER_TEST(VLAN, UnexpectedEndofBuffer, vlan_endof, net::ParseError::UnexpectedEof, parseVlan)