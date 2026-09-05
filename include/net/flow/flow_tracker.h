#pragma once

#include <net/capture/capture.h>
#include <net/capture/packet.h>
#include <net/flow/flow_key.h>
#include <net/flow/tcp_reassembler.h>

#include <cstring>
#include <unordered_map>

namespace net {

struct FlowApplications;

class FlowTable {
public:
    struct FlowStats {
        uint64_t packets = 0;
        uint64_t bytes = 0;
    };

    struct Flow {
        uint64_t first_seen = 0;
        uint64_t last_seen = 0;
        FlowStats fwd_stats;
        FlowStats rev_stats;
        TcpReassembler fwd_tcp;
        TcpReassembler rev_tcp;
        bool is_reverse = false;
        FlowApplications* app_state = nullptr;

        constexpr uint64_t totalPackets() const noexcept { return fwd_stats.packets + rev_stats.packets; }
        constexpr uint64_t totalBytes() const noexcept { return fwd_stats.bytes + rev_stats.bytes; }
        constexpr uint64_t durationUs() const noexcept { return last_seen - first_seen; }

        double payloadPercent(uint64_t total_bytes_all) const {
            if (total_bytes_all == 0) return 0.0;
            return 100.0 * static_cast<double>(totalBytes()) / static_cast<double>(total_bytes_all);
        }
    };

    static constexpr uint64_t DEFAULT_IDLE_TIMEOUT_US = 30000000;

    explicit FlowTable(uint64_t active_timeout_us = 0, uint64_t idle_timeout_us = DEFAULT_IDLE_TIMEOUT_US)
        : active_timeout_us_(active_timeout_us), idle_timeout_us_(idle_timeout_us) {}

    ParseError addPacket(const net::pcap::Capture& capture, FlowKey* out_key = nullptr, bool* out_is_new = nullptr, Flow** out_flow = nullptr);
    void flush();

    std::unordered_map<FlowKey, Flow, FlowKeyHash>& flows() { return flows_; }
    const std::unordered_map<FlowKey, Flow, FlowKeyHash>& flows() const { return flows_; }
    const std::vector<std::pair<FlowKey, Flow>>& completed() const { return completed_; }
    uint64_t total_bytes() const { return total_bytes_; }
    const std::vector<std::pair<const FlowKey*, const FlowTable::Flow*>> allFlows() const;

private:
    uint64_t active_timeout_us_ = 0;
    uint64_t idle_timeout_us_ = DEFAULT_IDLE_TIMEOUT_US;
    uint64_t total_bytes_ = 0;
    std::unordered_map<FlowKey, Flow, FlowKeyHash> flows_;
    std::vector<std::pair<FlowKey, Flow>> completed_;

    ParseError keyFromPacket(const Packet& pkt, FlowKey& out, bool& is_reverse);
    bool setPorts(const net::Packet::TransportHeader transport, FlowKey& out);
    bool setNetwork(const net::Packet::NetworkHeader network, FlowKey& out);
    
    bool isExpired(const FlowTable::Flow& flow, uint64_t ts_us) const;
};

}
