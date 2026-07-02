#include <gtest/gtest.h>
#include <net/core/parse_error.h>
#include <net/core/endian.h>
#include <net/protocols/tcp.h>
#include "../common/header_tester.h"
#include "../testgen/protocol_generator.h"

namespace {    
    inline constexpr uint8_t ipv4_pseudo[] = {
        0x45,
        0x00,
        0x00, 0x28,
        0x56, 0x78,
        0x40, 0x00,
        0x40,
        0x06,
        0x8C, 0x2C,
        0xAC, 0x10, 0x00, 0x0A,
        0xAC, 0x10, 0x00, 0x01,
    };
    inline constexpr uint8_t ipv4_pseudo_options[] = {
        0x45,
        0x00,
        0x00, 0x2C,
        0xF3, 0xB1,
        0x40, 0x00,
        0x3F,
        0x06,
        0xCA, 0x7B,
        0x0A, 0x4D, 0x93, 0x7E,
        0xC0, 0xA8, 0x1F, 0x2B,
    };
    inline constexpr uint8_t ipv6_pseudo[] = {
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x14,
        0x06,
        0x40,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd,
    };
    inline constexpr uint8_t tcp_v4_options_valid[] = {
        0x43, 0x21,
        0x12, 0x34,
        0x87, 0x65, 0x43, 0x28,
        0x00, 0x00, 0x00, 0x00,
        0x50, 
        0x02,
        0x6D, 0x10,
        0x1F, 0x8F,
        0x00, 0x00,
        0xBA, 0xBE, 0xCA, 0xFE,
    };
    inline constexpr uint8_t tcp_v4_endof[] = {
        0xc3, 0x50,
        0x00, 0x50,
        0x12, 0x34, 0x56, 0x78,
        0x00, 0x00, 0x00, 0x00,
        0x50,
        0x02,
        0x71, 0x10,
        0xBA, 0x59,
        0x00,
    };
    inline constexpr uint8_t tcp_v4_malformed[] = {
        0xc3, 0x50,
        0x00, 0x50,
        0x12, 0x34, 0x56, 0x78,
        0x00, 0x00, 0x00, 0x00,
        0x40, 
        0x02,
        0x71, 0x10,
        0xBA, 0x59,
        0x00, 0x00,
    };
    inline constexpr uint8_t tcp_v6_checksum[] = {
        0xc3, 0x5a,
        0x00, 0x50,
        0x12, 0x34, 0x56, 0x78,
        0x00, 0x00, 0x00, 0x00,
        0x50, 
        0x02,
        0x71, 0x10,
        0xBA, 0x59,
        0x00, 0x00,
    };
}

template <typename IpHeader, size_t N>
auto parseTcp(const uint8_t (&pseudo_header)[N]) {
    using ParseFn =
        net::ParseError (*)(
            std::span<const uint8_t>&,
            net::tcp::Header&,
            const IpHeader&,
            net::Endian);
    
    IpHeader header = test::makePseudoHeader<IpHeader>(pseudo_header);

    return test::bindHeaderParser<
        ParseFn,
        net::tcp::Header
    >(
        static_cast<ParseFn>(net::tcp::parse),
        header,
        net::Endian::Big
    );
}

RANDOMIZED_TEST(TCP, RandomizedIPv4, g_randomizedIterations / 2, [](uint8_t* data) {testgen::makeTcpHeader(data, test::makePseudoHeader<net::ip::v4::Header>(ipv4_pseudo), 5);}, parseTcp<net::ip::v4::Header>(ipv4_pseudo))
RANDOMIZED_TEST(TCP, RandomizedIPv6, g_randomizedIterations / 2, [](uint8_t* data) {testgen::makeTcpHeader(data, test::makePseudoHeader<net::ip::v6::Header>(ipv6_pseudo), 5);}, parseTcp<net::ip::v6::Header>(ipv6_pseudo))
HEADER_TEST(TCP, ParsesValidOptionsIPv4, tcp_v4_options_valid, net::ParseError::None, parseTcp<net::ip::v4::Header>(ipv4_pseudo_options))
HEADER_TEST(TCP, UnexpectedEndofBuffer, tcp_v4_endof, net::ParseError::UnexpectedEof, parseTcp<net::ip::v4::Header>(ipv4_pseudo))
HEADER_TEST(TCP, RejectsMalformedHeader, tcp_v4_malformed, net::ParseError::MalformedHeader, parseTcp<net::ip::v4::Header>(ipv4_pseudo))
HEADER_TEST(TCP, RejectsChecksumMismatch, tcp_v6_checksum, net::ParseError::ChecksumMismatch, parseTcp<net::ip::v6::Header>(ipv6_pseudo))