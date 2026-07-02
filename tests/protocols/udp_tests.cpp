#include <gtest/gtest.h>
#include <net/core/parse_error.h>
#include <net/core/endian.h>
#include <net/protocols/udp.h>
#include "../common/header_tester.h"
#include "../testgen/protocol_generator.h"

namespace {   
    inline constexpr uint8_t ipv4_pseudo[] = {
        0x45,
        0x00,
        0x00, 0x1C,
        0x12, 0x34,
        0x40, 0x00,
        0x40,
        0x06,
        0xA4, 0xF2,
        0xC0, 0xA8, 0x01, 0x64,
        0xC0, 0xA8, 0x01, 0x01,
    };
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
    inline constexpr uint8_t udp_v4_endof[] = {
        0xC0, 0x23,
        0x00, 0x50,
        0x00, 0x08,
        0x00,
    };
    inline constexpr uint8_t udp_v6_malformed[] = {
        0xC0, 0x23,
        0x00, 0x50,
        0x00, 0x0C,
        0x00, 0x00,
    };
    inline constexpr uint8_t udp_v4_checksum[] = {
        0xC0, 0x23,
        0x00, 0x50,
        0x00, 0x08,
        0x00, 0x01,
    };
}

template <typename IpHeader, size_t N>
auto parseUdp(const uint8_t (&pseudo_header)[N]) {
    using ParseFn =
        net::ParseError (*)(
            std::span<const uint8_t>&,
            net::udp::Header&,
            const IpHeader&,
            net::Endian);

    IpHeader header = test::makePseudoHeader<IpHeader>(pseudo_header);

    return test::bindHeaderParser<
        ParseFn,
        net::udp::Header
    >(
        static_cast<ParseFn>(net::udp::parse),
        header,
        net::Endian::Big
    );
}

RANDOMIZED_TEST(UDP, RandomizedIPv4, g_randomizedIterations / 2, [](uint8_t* data) {testgen::makeUdpHeader(data, test::makePseudoHeader<net::ip::v4::Header>(ipv4_pseudo));}, parseUdp<net::ip::v4::Header>(ipv4_pseudo))
RANDOMIZED_TEST(UDP, RandomizedIPv6, g_randomizedIterations / 2, [](uint8_t* data) {testgen::makeUdpHeader(data, test::makePseudoHeader<net::ip::v6::Header>(ipv6_pseudo));}, parseUdp<net::ip::v6::Header>(ipv6_pseudo))
HEADER_TEST(UDP, UnexpectedEndofBuffer, udp_v4_endof, net::ParseError::UnexpectedEof, parseUdp<net::ip::v4::Header>(ipv4_pseudo))
HEADER_TEST(UDP, RejectsMalformedHeader, udp_v6_malformed, net::ParseError::MalformedHeader, parseUdp<net::ip::v6::Header>(ipv6_pseudo))
HEADER_TEST(UDP, RejectsChecksumMismatch, udp_v4_checksum, net::ParseError::ChecksumMismatch, parseUdp<net::ip::v4::Header>(ipv4_pseudo))