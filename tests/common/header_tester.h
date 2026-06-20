#pragma once

#include <gtest/gtest.h>
#include <net/core/parse_error.h>
#include <net/core/endian.h>
#include <tuple>
#include <utility>

namespace test {

template <typename ParseFn, size_t N>
void runHeaderTest(const uint8_t (&data)[N], net::ParseError expected, ParseFn&& parseFn) {
    std::span<uint8_t> span{data, N};
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
           (std::span<uint8_t>& span) mutable {

        Header header{};

        return std::apply(
            [&](auto&&... inner) {
                return fn(span, header,
                          std::forward<decltype(inner)>(inner)...);
            },
            stored);
    };
}

}

#define HEADER_TEST(SUITE_NAME, TEST_NAME, DATA, EXPECTED_ERROR, PARSE_FN) \
    TEST(SUITE_NAME, TEST_NAME) { \
        test::runHeaderTest(DATA, EXPECTED_ERROR, PARSE_FN); \
    }
