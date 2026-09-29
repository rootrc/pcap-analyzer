#include <gtest/gtest.h>
#include <net/decode/app_decoder.h>
#include "common/header_tester.h"
#include "testgen/protocol_generator.h"

#include <string_view>
#include <vector>

namespace {
    constexpr uint32_t ISN = 5000;
    constexpr uint16_t CLIENT_PORT = 40000;

    inline constexpr uint8_t dns_truncated[] = {
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
    };

    inline constexpr std::string_view http_get_one = "GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n";
    inline constexpr std::string_view http_get_two = "GET /two HTTP/1.1\r\nHost: example.com\r\n\r\n";
    inline constexpr std::string_view http_bad_request_line = "&$(} /data\r\nHost: example.com\r\n\r\n";

    net::FlowKey makeKey(uint16_t src_port, uint16_t dst_port) {
        net::FlowKey key{};
        key.isIpv4 = true;
        key.src_ip[0] = 10;  key.src_ip[3] = 1;
        key.dst_ip[0] = 192; key.dst_ip[1] = 168; key.dst_ip[3] = 1;
        key.src_port = src_port;
        key.dst_port = dst_port;
        key.protocol = net::ip::PROTOCOL_TCP;
        return key;
    }

    void append(std::vector<uint8_t>& out, std::span<const uint8_t> bytes) {
        out.insert(out.end(), bytes.begin(), bytes.end());
    }

    void appendDnsMessage(std::vector<uint8_t>& out, std::span<const uint8_t> message) {
        out.push_back(static_cast<uint8_t>(message.size() >> 8));
        out.push_back(static_cast<uint8_t>(message.size() & 0xFF));
        append(out, message);
    }

    void appendText(std::vector<uint8_t>& out, std::string_view text) {
        out.insert(out.end(), text.begin(), text.end());
    }

    void appendRandomDnsMessage(std::vector<uint8_t>& out) {
        uint8_t buffer[16384]{};
        appendDnsMessage(out, std::span<const uint8_t>{buffer, testgen::makeDnsHeader(buffer)});
    }

    class Direction {
    public:
        Direction(uint16_t src_port, uint16_t dst_port)
            : decoder_(dnsTable_), key_(makeKey(src_port, dst_port)) {
            flow_.fwd_tcp.onSent(testgen::makeTcpSegmentHeader(ISN), std::span<const uint8_t>{});
        }

        void send(const std::vector<uint8_t>& stream, size_t offset, size_t len) {
            flow_.fwd_tcp.onSent(testgen::makeTcpSegmentHeader(static_cast<uint32_t>(ISN + offset)),
                                 std::span<const uint8_t>{stream.data() + offset, len});
            decoder_.pollFlow(key_, flow_, first_);
            first_ = false;
        }

        void sendAll(const std::vector<uint8_t>& stream) { send(stream, 0, stream.size()); }

        const net::Applications* applications() { return decoder_.getApplications(key_, false); }
        size_t unconsumed() const { return flow_.fwd_tcp.available(); }

    private:
        net::DnsTable dnsTable_;
        net::AppDecoder decoder_;
        net::FlowKey key_;
        net::FlowTable::Flow flow_;
        bool first_ = true;
    };
}

TEST(APP_DECODER, DecodesLengthPrefixedDnsOverTcp) {
    std::vector<uint8_t> stream;
    appendRandomDnsMessage(stream);
    appendRandomDnsMessage(stream);

    Direction direction(CLIENT_PORT, net::dns::PORT);
    const size_t first = stream.size() / 3;
    const size_t second = (stream.size() * 2) / 3;
    direction.send(stream, first, second - first);
    direction.send(stream, second, stream.size() - second);
    direction.send(stream, 0, first);

    const net::Applications* apps = direction.applications();
    ASSERT_NE(apps, nullptr);
    EXPECT_EQ(apps->dns_messages.size(), 2u);
    EXPECT_EQ(apps->decode_failures, 0u);
    EXPECT_EQ(direction.unconsumed(), 0u);
}

TEST(APP_DECODER, SkipsMalformedDnsMessageExactly) {
    std::vector<uint8_t> stream;
    appendRandomDnsMessage(stream);
    appendDnsMessage(stream, dns_truncated);
    appendRandomDnsMessage(stream);

    Direction direction(net::dns::PORT, CLIENT_PORT);
    direction.sendAll(stream);

    const net::Applications* apps = direction.applications();
    ASSERT_NE(apps, nullptr);
    EXPECT_EQ(apps->dns_messages.size(), 2u) << "a bad message stopped the whole stream";
    EXPECT_EQ(apps->decode_failures, 1u);
    EXPECT_EQ(direction.unconsumed(), 0u) << "the malformed message was not skipped exactly";
}

TEST(APP_DECODER, DecodesPipelinedHttpRequests) {
    std::vector<uint8_t> stream;
    appendText(stream, http_get_one);
    appendText(stream, http_get_two);

    Direction direction(CLIENT_PORT, net::http::PORT);
    direction.send(stream, 0, 10);
    direction.send(stream, 10, 45);
    direction.send(stream, 55, stream.size() - 55);

    const net::Applications* apps = direction.applications();
    ASSERT_NE(apps, nullptr);
    ASSERT_EQ(apps->http_messages.size(), 2u);
    EXPECT_EQ(apps->http_messages[0].target, "/one");
    EXPECT_EQ(apps->http_messages[1].target, "/two");
    EXPECT_EQ(apps->decode_failures, 0u);
    EXPECT_EQ(direction.unconsumed(), 0u);
}

TEST(APP_DECODER, ResynchronizesAfterMalformedHttp) {
    std::vector<uint8_t> stream;
    appendText(stream, http_bad_request_line);
    appendText(stream, http_get_one);

    Direction direction(CLIENT_PORT, net::http::PORT);
    direction.sendAll(stream);

    const net::Applications* apps = direction.applications();
    ASSERT_NE(apps, nullptr);
    ASSERT_EQ(apps->http_messages.size(), 1u) << "resync did not find the next request line";
    EXPECT_EQ(apps->http_messages[0].target, "/one");
    EXPECT_EQ(apps->decode_failures, 1u);
}

TEST(APP_DECODER, IgnoresFlowsOnUndecodedPorts) {
    std::vector<uint8_t> stream;
    appendText(stream, http_get_one);

    Direction direction(CLIENT_PORT, 8080);
    direction.sendAll(stream);

    EXPECT_EQ(direction.applications(), nullptr);
}
