#pragma once

#include <gtest/gtest.h>
#include <net/core/parse_error.h>
#include <net/core/endian.h>
#include "../testgen/protocol_generator.h"

#include <tuple>
#include <utility>

namespace test {

template <typename ParseFn, size_t N>
void runHeaderTest(const uint8_t (&data)[N], net::ParseError expected, ParseFn&& parseFn) {
    std::span<const uint8_t> span{data, N};
    net::ParseError result = parseFn(span);

    EXPECT_EQ(result, expected)
        << "Expected: " << net::toString(expected)
        << ", Got: " << net::toString(result)
        << " (data size: " << N << " bytes)";
}

template <typename ParseFn, typename Header, typename... Args>
auto bindHeaderParser(ParseFn&& fn, Args&&... args) {
    auto stored = std::make_tuple(std::forward<Args>(args)...);

    return [fn = std::forward<ParseFn>(fn),
            stored = std::move(stored)]
           (std::span<const uint8_t>& span) mutable {

        Header header{};

        return std::apply(
            [&](auto&&... inner) {
                return fn(span, header,
                          std::forward<decltype(inner)>(inner)...);
            },
            stored);
    };
}

template <typename GeneratorFn, typename ParseFn>
void runRandomizedTest(size_t iterations, GeneratorFn&& generator, ParseFn&& parseFn) {
    for (size_t i = 0; i < iterations; ++i) {
        uint8_t data[2048]{};

        generator(data);

        runHeaderTest(data, net::ParseError::None, parseFn);
    }
}

template <typename IpHeader, size_t N>
auto makePseudoHeader(const uint8_t (&pseudo_header)[N]) {
    std::span<const uint8_t> span{pseudo_header, N};
    IpHeader header{};
    parse(span, header, net::Endian::Big);
    return header;
}

}

#define HEADER_TEST(SUITE_NAME, TEST_NAME, DATA, EXPECTED_ERROR, PARSE_FN) \
    TEST(SUITE_NAME, TEST_NAME) { \
        test::runHeaderTest(DATA, EXPECTED_ERROR, PARSE_FN); \
    }

#define RANDOMIZED_TEST(SUITE_NAME, TEST_NAME, ITERATIONS, GENERATOR, PARSER) \
    TEST(SUITE_NAME, TEST_NAME) { \
        test::runRandomizedTest(ITERATIONS, GENERATOR, PARSER); \
    }
