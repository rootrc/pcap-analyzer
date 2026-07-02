#include <gtest/gtest.h>
#include <net/core/parse_error.h>
#include <net/core/endian.h>
#include <net/protocols/arp.h>
#include "../common/header_tester.h"
#include "../testgen/protocol_generator.h"

namespace {    
    inline constexpr uint8_t arp_endof[] = {
        0x00, 0x01,
        0x08, 0x00,
        0x06,
        0x04,
        0x00,
    };
    inline constexpr uint8_t arp_endof_address[] = {
        0x00, 0x01,
        0x08, 0x00,
        0x06,
        0x04,
        0x00, 0x01,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xc0, 0xA8, 0x01, 0x64,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0xA8, 0x01,
    };
    inline constexpr uint8_t arp_endof_field_hlen[] = {
        0x00, 0x01,
        0x08, 0x00,
        0x00,
        0x04,
        0x00, 0x01,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xc0, 0xA8, 0x01, 0x64,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0xA8, 0x01, 0x01,
    };
    inline constexpr uint8_t arp_endof_field_oper[] = {
        0x00, 0x01,
        0x08, 0x00,
        0x06,
        0x04,
        0xFF, 0x01,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xc0, 0xA8, 0x01, 0x64,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0xA8, 0x01, 0x01,
    };
}

auto parseArp = test::bindHeaderParser<
    decltype(net::arp::parse),
    net::arp::Header
>(
    net::arp::parse,
    net::Endian::Big
);

RANDOMIZED_TEST(ARP, Randomized, g_randomizedIterations, [](uint8_t* data) {testgen::makeArpHeader(data);}, parseArp)
HEADER_TEST(ARP, UnexpectedEndofBuffer, arp_endof, net::ParseError::UnexpectedEof, parseArp)
HEADER_TEST(ARP, UnexpectedEndofBufferAddress, arp_endof_address, net::ParseError::UnexpectedEof, parseArp)
HEADER_TEST(ARP, RejectsInvalidFieldValueHlen, arp_endof_field_hlen, net::ParseError::InvalidFieldValue, parseArp)
HEADER_TEST(ARP, RejectsInvalidFieldValueOper, arp_endof_field_oper, net::ParseError::InvalidFieldValue, parseArp)