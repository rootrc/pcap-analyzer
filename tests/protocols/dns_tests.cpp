#include <gtest/gtest.h>
#include <net/protocols/arp.h>
#include "../common/header_tester.h"
#include "../testgen/protocol_generator.h"

namespace {    
    inline constexpr uint8_t dns_endof[] = {
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00,
    };
    inline constexpr uint8_t dns_question_endof[] = {
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m',
        0x00,
        0x00, 0x01,
        0x00,
    };
    inline constexpr uint8_t dns_name_endof[] = {
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m',
        0x00, 0x01,
        0x00, 0x01,
    };
    inline constexpr uint8_t dns_name_compression_long[] = {
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0xC0, 0x0E,
        0xC0, 0x10,
        0xC0, 0x12,
        0xC0, 0x14,
        0xC0, 0x16,
        0xC0, 0x18,
        0xC0, 0x1A,
        0xC0, 0x1C,
        0xC0, 0x1E,
        0xC0, 0x20,
        0xC0, 0x22,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    };
    inline constexpr uint8_t dns_name_compression_invalid[] = {
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0xB0,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    };
}

auto parseDns = test::bindHeaderParser<
    decltype(net::dns::parse),
    net::dns::Header
>(
    net::dns::parse,
    net::Endian::Big
);

RANDOMIZED_TEST(DNS, Randomized, g_randomizedIterations, [](uint8_t* data) {testgen::makeDnsHeader(data);}, parseDns)
HEADER_TEST(DNS, UnexpectedEndofBuffer, dns_endof, net::ParseError::UnexpectedEof, parseDns)
HEADER_TEST(DNS, UnexpectedEndofBufferQuestion, dns_question_endof, net::ParseError::UnexpectedEof, parseDns)
HEADER_TEST(DNS, UnexpectedEndofBufferName, dns_name_endof, net::ParseError::UnexpectedEof, parseDns)
HEADER_TEST(DNS, RejectsMalformedHeaderNameCompressionTooLong, dns_name_compression_long, net::ParseError::MalformedHeader, parseDns)
HEADER_TEST(DNS, RejectsMalformedHeaderNameCompressionInvalid, dns_name_compression_invalid, net::ParseError::MalformedHeader, parseDns)