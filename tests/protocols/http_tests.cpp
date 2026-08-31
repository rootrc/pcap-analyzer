#include <gtest/gtest.h>
#include <net/protocols/http.h>
#include "../common/header_tester.h"
#include "../testgen/protocol_generator.h"

namespace {    
    inline constexpr std::string_view http_endof = "abcdefg";
    inline constexpr std::string_view http_missing_cr = "HTTP/1.1 200 OK\nHost: Example.com\r\n\r\n";
    inline constexpr std::string_view http_missing_lf = "GET /data HTTP/1.1\rHost: Example.com\r\n\r\n";
    inline constexpr std::string_view http_startline_empty = "\r\nHost: Example.com\r\n\r\n";
    inline constexpr std::string_view http_startline_space = "HTTP/1.1200OK\r\nHost: Example.com\r\n\r\n";
    inline constexpr std::string_view http_invalid_status = "HTTP/1.1 ABC OK\r\nHost: Example.com\r\n\r\n";
    inline constexpr std::string_view http_missing_version = "GET /data\r\nHost: Example.com\r\n\r\n";
    inline constexpr std::string_view http_invalid_request_token = "&$(} /data\r\nHost: Example.com\r\n\r\n";
    inline constexpr std::string_view http_unsupported_version = "GET /data HTTP/2.0\r\nHost: Example.com\r\n\r\n";
    inline constexpr std::string_view http_field_space = "HTTP/1.1 200 OK\r\n Host: Example.com\r\n\r\n";
    inline constexpr std::string_view http_field_tab = "POST /data HTTP/1.1\r\n\tHost: Example.com\r\n\r\n";
    inline constexpr std::string_view http_field_missing_colon = "HTTP/1.1 200 OK\r\nHost Example.com\r\n\r\n";
    inline constexpr std::string_view http_field_missing_name = "POST /data HTTP/1.1\r\n: Example.com\r\n\r\n";
    inline constexpr std::string_view http_field_colon_space = "HTTP/1.1 200 OK\r\n : Example.com\r\n\r\n";
    inline constexpr std::string_view http_field_colon_tab = "POST /data HTTP/1.1\r\nHost\t: Example.com\r\n\r\n";
    inline constexpr std::string_view http_field_invalid_token = "HTTP/1.1 200 OK\r\n[+^`: Example.com\r\n\r\n";
    inline constexpr std::string_view http_field_value_lf = "POST /data HTTP/1.1\r\nHost: Example\n.com\r\n\r\n";
    inline constexpr std::string_view http_field_value_null{"HTTP/1.1 200 OK\r\nHost: Example\0.com\r\n\r\n",sizeof("HTTP/1.1 200 OK\r\nHost: Example\0.com\r\n\r\n") - 1};
    inline constexpr std::string_view http_dup_content_length = "POST /data HTTP/1.1\r\nContent-Length: 4321\r\nContent-Length: 1234\r\n\r\n";
    inline constexpr std::string_view http_transfer_encoding_and_content_length = "POST /data HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 1234\r\n\r\n";
    inline constexpr std::string_view http_invalid_transfer_encoding = "POST /data HTTP/1.1\r\nTransfer-Encoding: chunk\r\n\r\n";
    inline constexpr std::string_view http_invalid_decimal_content_length = "POST /data HTTP/1.1\r\nContent-Length: abcd\r\n\r\n";
    inline constexpr std::string_view http_over_limit_content_length = "POST /data HTTP/1.1\r\nContent-Length: 999999999999999999999999999999999999999999999\r\n\r\n";

    inline constexpr std::string_view chunk_size_empty = ";ext\r\n0\r\n\r\n";
    inline constexpr std::string_view chunk_size_invalid_hex = "xyz\r\n0\r\n\r\n";
    inline constexpr std::string_view chunk_data_truncated = "4\r\nWi";
    inline constexpr std::string_view chunk_terminator_eof = "4\r\nWiki";
    inline constexpr std::string_view chunk_terminator_missing_lf = "4\r\nWiki\rX0\r\n\r\n";
    inline constexpr std::string_view chunk_terminator_not_empty = "4\r\nWikiXX\r\n0\r\n\r\n";
    inline constexpr std::string_view chunk_trailer_eof = "4\r\nWiki\r\n0\r\n";
    inline constexpr std::string_view chunk_trailer_malformed = "0\r\nBad Header\r\n\r\n";
}

auto parseHttp = test::bindHeaderParser<
    decltype(net::http::parse),
    net::http::Header
>(
    net::http::parse
);

auto parseChunked = [](std::span<const uint8_t>& span) {
    return net::http::parseChunkedBody(span);
};

RANDOMIZED_TEST(HTTP, Randomized, g_randomizedIterations, [](uint8_t* data) {testgen::makeHttpHeader(data);}, parseHttp)
HEADER_TEST(HTTP, UnexpectedEndofBuffer, http_endof, net::ParseError::UnexpectedEof, parseHttp)
HEADER_TEST(HTTP, RejectsMissingCarriageReturn, http_missing_cr, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsMissingLineFeed, http_missing_lf, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsMissingStartLine, http_startline_empty, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsMissingStartLineSpace, http_startline_space, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsInvalidStatus, http_invalid_status, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsMissingVersion, http_missing_version, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsInvalidToken, http_invalid_request_token, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsUnsupportedVersion, http_unsupported_version, net::ParseError::UnsupportedVersion, parseHttp)
HEADER_TEST(HTTP, RejectsFieldSpace, http_field_space, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsFieldTab, http_field_tab, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsFieldMissingColon, http_field_missing_colon, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsFieldMissingName, http_field_missing_name, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsFieldColonSpace, http_field_colon_space, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsFieldColonTab, http_field_colon_tab, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsFieldInvalidToken, http_field_invalid_token, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsFieldValueLineFeed, http_field_value_lf, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsFieldValueNullChar, http_field_value_null, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsDuplicateContentLength, http_dup_content_length, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsTransferEncodingAndContentLength, http_transfer_encoding_and_content_length, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsInvalidTransferEncoding, http_invalid_transfer_encoding, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsInvalidDecimalContentLength, http_invalid_decimal_content_length, net::ParseError::MalformedHeader, parseHttp)
HEADER_TEST(HTTP, RejectsInvalidLimitContentLength, http_over_limit_content_length, net::ParseError::MalformedHeader, parseHttp)

HEADER_TEST(HTTP, RejectsEmptyChunkSize, chunk_size_empty, net::ParseError::MalformedHeader, parseChunked)
HEADER_TEST(HTTP, RejectsInvalidHexChunkSize, chunk_size_invalid_hex, net::ParseError::MalformedHeader, parseChunked)
HEADER_TEST(HTTP, RejectsTruncatedChunkData, chunk_data_truncated, net::ParseError::UnexpectedEof, parseChunked)
HEADER_TEST(HTTP, RejectsChunkTerminatorUnexpectedEof, chunk_terminator_eof, net::ParseError::UnexpectedEof, parseChunked)
HEADER_TEST(HTTP, RejectsChunkTerminatorMissingLineFeed, chunk_terminator_missing_lf, net::ParseError::MalformedHeader, parseChunked)
HEADER_TEST(HTTP, RejectsNonEmptyChunkTerminator, chunk_terminator_not_empty, net::ParseError::MalformedHeader, parseChunked)
HEADER_TEST(HTTP, RejectsTrailerUnexpectedEof, chunk_trailer_eof, net::ParseError::UnexpectedEof, parseChunked)
HEADER_TEST(HTTP, RejectsMalformedTrailerField, chunk_trailer_malformed, net::ParseError::MalformedHeader, parseChunked)