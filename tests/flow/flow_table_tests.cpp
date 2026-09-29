#include <gtest/gtest.h>
#include <net/flow/flow_table.h>
#include "common/header_tester.h"

#include <cstring>

namespace {
    constexpr uint32_t CLIENT_IP = 0x0A000001;
    constexpr uint32_t SERVER_IP = 0xC0A80001;
    constexpr uint32_t OTHER_IP = 0x0A000002;
    constexpr uint16_t CLIENT_PORT = 40000;

    net::pcap::Capture makeTcpCapture(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port,
                                      uint16_t dst_port, uint64_t ts_us, uint32_t len) {
        net::pcap::Capture capture{};
        capture.ts_us = ts_us;
        capture.packetHeader.incl_len = len;

        net::ip::v4::Header ip{};
        ip.version_ihl = 0x45;
        ip.protocol = net::ip::PROTOCOL_TCP;
        ip.src_ip = src_ip;
        ip.dst_ip = dst_ip;
        capture.pkt.network = ip;

        net::tcp::Header tcp{};
        tcp.data_offset_reserved = 0x50;
        tcp.src_port = src_port;
        tcp.dst_port = dst_port;
        capture.pkt.transport = tcp;

        return capture;
    }
}

TEST(FLOW_TABLE, MergesBothDirectionsIntoOneFlow) {
    net::FlowTable table;
    bool is_new = false;

    ASSERT_EQ(table.addPacket(makeTcpCapture(CLIENT_IP, SERVER_IP, CLIENT_PORT, net::http::PORT, 1000, 100),
                              nullptr, &is_new), net::ParseError::None);
    EXPECT_TRUE(is_new);
    ASSERT_EQ(table.addPacket(makeTcpCapture(SERVER_IP, CLIENT_IP, net::http::PORT, CLIENT_PORT, 2000, 200),
                              nullptr, &is_new), net::ParseError::None);
    EXPECT_FALSE(is_new) << "the reverse direction started a second flow";

    ASSERT_EQ(table.flows().size(), 1u) << "a bidirectional connection was split into one-way flows";
    const net::FlowTable::Flow& flow = table.flows().begin()->second;
    EXPECT_EQ(flow.fwd_stats.packets, 1u);
    EXPECT_EQ(flow.fwd_stats.bytes, 100u);
    EXPECT_EQ(flow.rev_stats.packets, 1u);
    EXPECT_EQ(flow.rev_stats.bytes, 200u);
    EXPECT_EQ(table.total_bytes(), 300u);
}

TEST(FLOW_TABLE, NormalizesStoredAndReportedKey) {
    net::FlowTable table;
    net::FlowKey reported{};

    ASSERT_EQ(table.addPacket(makeTcpCapture(SERVER_IP, CLIENT_IP, net::http::PORT, CLIENT_PORT, 1000, 100),
                              &reported), net::ParseError::None);

    ASSERT_EQ(table.flows().size(), 1u);
    const net::FlowKey& stored = table.flows().begin()->first;
    EXPECT_LT(std::memcmp(stored.src_ip, stored.dst_ip, 16), 0);
    const uint16_t stored_src_port = stored.src_port;
    const uint16_t stored_dst_port = stored.dst_port;
    EXPECT_EQ(stored_src_port, CLIENT_PORT);
    EXPECT_EQ(stored_dst_port, net::http::PORT);
    EXPECT_TRUE(reported == stored) << "the key handed back to the caller is not the stored key";
    EXPECT_TRUE(table.flows().begin()->second.is_reverse);
}

TEST(FLOW_TABLE, IdleTimeoutMovesFlowToCompleted) {
    net::FlowTable table;
    const uint64_t idle = net::FlowTable::DEFAULT_IDLE_TIMEOUT_US;

    ASSERT_EQ(table.addPacket(makeTcpCapture(CLIENT_IP, SERVER_IP, CLIENT_PORT, net::http::PORT, 0, 100)),
              net::ParseError::None);
    ASSERT_EQ(table.addPacket(makeTcpCapture(CLIENT_IP, SERVER_IP, CLIENT_PORT, net::http::PORT, idle + 1, 200)),
              net::ParseError::None);

    ASSERT_EQ(table.completed().size(), 1u);
    EXPECT_EQ(table.completed()[0].second.totalBytes(), 100u);
    ASSERT_EQ(table.flows().size(), 1u);
    EXPECT_EQ(table.flows().begin()->second.totalBytes(), 200u);
}

TEST(FLOW_TABLE, ActiveTimeoutMovesFlowToCompleted) {
    net::FlowTable table(10000000);

    ASSERT_EQ(table.addPacket(makeTcpCapture(CLIENT_IP, SERVER_IP, CLIENT_PORT, net::http::PORT, 0, 100)),
              net::ParseError::None);
    ASSERT_EQ(table.addPacket(makeTcpCapture(CLIENT_IP, SERVER_IP, CLIENT_PORT, net::http::PORT, 5000000, 100)),
              net::ParseError::None);
    EXPECT_TRUE(table.completed().empty()) << "expired while inside both timeouts";

    ASSERT_EQ(table.addPacket(makeTcpCapture(CLIENT_IP, SERVER_IP, CLIENT_PORT, net::http::PORT, 10000001, 300)),
              net::ParseError::None);
    ASSERT_EQ(table.completed().size(), 1u);
    EXPECT_EQ(table.completed()[0].second.totalPackets(), 2u);
    ASSERT_EQ(table.flows().size(), 1u);
    EXPECT_EQ(table.flows().begin()->second.totalBytes(), 300u);
}

TEST(FLOW_TABLE, AllFlowsSpansCompletedAndActiveSortedByBytes) {
    net::FlowTable table;
    const uint64_t idle = net::FlowTable::DEFAULT_IDLE_TIMEOUT_US;

    table.addPacket(makeTcpCapture(CLIENT_IP, SERVER_IP, CLIENT_PORT, net::http::PORT, 0, 1000));
    table.addPacket(makeTcpCapture(CLIENT_IP, SERVER_IP, CLIENT_PORT, net::http::PORT, idle + 1, 5000));
    table.addPacket(makeTcpCapture(OTHER_IP, SERVER_IP, CLIENT_PORT, net::http::PORT, idle + 2, 3000));

    const auto flows = table.allFlows();
    ASSERT_EQ(flows.size(), 3u);
    EXPECT_EQ(flows[0].second->totalBytes(), 5000u);
    EXPECT_EQ(flows[1].second->totalBytes(), 3000u);
    EXPECT_EQ(flows[2].second->totalBytes(), 1000u);
}

TEST(FLOW_TABLE, AllFlowsBreaksByteTiesByKey) {
    net::FlowTable table;
    for (uint16_t port : {40005, 40002, 40006, 40001, 40004, 40003}) {
        ASSERT_EQ(table.addPacket(makeTcpCapture(CLIENT_IP, SERVER_IP, port, net::http::PORT, 0, 1000)),
                  net::ParseError::None);
    }

    const auto flows = table.allFlows();
    ASSERT_EQ(flows.size(), 6u);
    for (size_t i = 1; i < flows.size(); ++i) {
        ASSERT_EQ(flows[i - 1].second->totalBytes(), flows[i].second->totalBytes());
        EXPECT_LT(std::memcmp(flows[i - 1].first, flows[i].first, sizeof(net::FlowKey)), 0)
            << "equal-byte flows came out in unordered_map order at index " << i;
    }
}

TEST(FLOW_TABLE, FlushMovesEveryFlowToCompleted) {
    net::FlowTable table;
    table.addPacket(makeTcpCapture(CLIENT_IP, SERVER_IP, CLIENT_PORT, net::http::PORT, 0, 100));
    table.addPacket(makeTcpCapture(OTHER_IP, SERVER_IP, CLIENT_PORT, net::http::PORT, 1, 200));

    table.flush();

    EXPECT_TRUE(table.flows().empty());
    EXPECT_EQ(table.completed().size(), 2u);
    EXPECT_EQ(table.allFlows().size(), 2u);
}

TEST(FLOW_TABLE, DisablesPayloadBufferingOffApplicationPorts) {
    net::FlowTable table;

    ASSERT_EQ(table.addPacket(makeTcpCapture(CLIENT_IP, SERVER_IP, CLIENT_PORT, 12345, 0, 100)),
              net::ParseError::None);
    ASSERT_EQ(table.flows().size(), 1u);
    const net::FlowTable::Flow& plain = table.flows().begin()->second;
    EXPECT_FALSE(plain.fwd_tcp.keep_payload);
    EXPECT_FALSE(plain.rev_tcp.keep_payload);

    net::FlowTable http_table;
    ASSERT_EQ(http_table.addPacket(makeTcpCapture(CLIENT_IP, SERVER_IP, CLIENT_PORT, net::http::PORT, 0, 100)),
              net::ParseError::None);
    ASSERT_EQ(http_table.flows().size(), 1u);
    const net::FlowTable::Flow& web = http_table.flows().begin()->second;
    EXPECT_TRUE(web.fwd_tcp.keep_payload);
    EXPECT_TRUE(web.rev_tcp.keep_payload);
}

TEST(FLOW_TABLE, IgnoresArpPackets) {
    net::FlowTable table;
    net::pcap::Capture capture{};
    capture.packetHeader.incl_len = 60;
    capture.pkt.network = net::arp::Header{};

    EXPECT_EQ(table.addPacket(capture), net::ParseError::None);
    EXPECT_TRUE(table.flows().empty());
    EXPECT_EQ(table.total_bytes(), 0u);
}

TEST(FLOW_TABLE, KeyFromPacketRejectsUnsupportedLayers) {
    net::Packet packet{};
    net::FlowKey key{};

    EXPECT_EQ(net::FlowTable::keyFromPacket(packet, key), net::ParseError::UnsupportedNetworkType);

    packet.network = net::ip::v4::Header{};
    EXPECT_EQ(net::FlowTable::keyFromPacket(packet, key), net::ParseError::UnsupportedTransportType);
}
