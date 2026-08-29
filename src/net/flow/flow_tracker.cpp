#include <net/flow/flow_tracker.h>

#include <algorithm>
#include <iomanip>

template<typename... Ts>
struct overload : Ts... { using Ts::operator()...; };

namespace net {

ParseError FlowTable::addPacket(const net::pcap::Capture& capture, FlowKey* out_key, bool* out_is_new, Flow** out_flow) {
    if (out_flow) *out_flow = nullptr;
    if (capture.pkt.isArp()) {
        return ParseError::None;
    }
    FlowKey key{};
    bool is_reverse = false;
    if (auto err = keyFromPacket(capture.pkt, key, is_reverse); err != ParseError::None) return err;
    if (out_key) *out_key = key;
    if (out_is_new) *out_is_new = false;

    total_bytes_ += capture.packetHeader.incl_len;

    std::unordered_map<net::FlowKey, net::FlowTable::Flow, net::FlowKeyHash>::iterator it = flows_.find(key);
    if (it != flows_.end() && isExpired(it->second, capture.ts_us)) {
        completed_.emplace_back(key, std::move(it->second));
        flows_.erase(it);
        it = flows_.end();
    }
    if (it == flows_.end()) {
        it = flows_.try_emplace(key).first;
        it->second.first_seen = capture.ts_us;
        if (out_is_new) *out_is_new = true;
    }

    Flow& flow = it->second;
    if (out_flow) *out_flow = &flow;
    flow.last_seen = capture.ts_us;
    flow.is_reverse = is_reverse;
    FlowStats& stats = flow.is_reverse ? flow.rev_stats : flow.fwd_stats;
    ++stats.packets;
    stats.bytes += capture.packetHeader.incl_len;

    if (capture.pkt.isTcp()) {
        TcpReassembler& self = flow.is_reverse ? flow.rev_tcp : flow.fwd_tcp;
        TcpReassembler& other = flow.is_reverse ? flow.fwd_tcp : flow.rev_tcp;
        self.onSent(*capture.pkt.tcp(), capture.pkt.payload);
        other.onReceived(*capture.pkt.tcp());
    }

    return ParseError::None;
}

ParseError FlowTable::keyFromPacket(const Packet& pkt, FlowKey& out, bool& is_reverse) {
    if (!setNetwork(pkt.network, out)) return ParseError::UnsupportedNetworkType;
    if (!setPorts(pkt.transport, out)) return ParseError::UnsupportedTransportType;
    is_reverse = out.normalize();
    return ParseError::None;
}

bool FlowTable::setNetwork(const net::Packet::NetworkHeader network, FlowKey& out) {
    return std::visit(overload{
        [&](const ip::v4::Header& v4) {
            for (size_t i = 0; i < 4; ++i) {
                out.src_ip[i] = (v4.src_ip >> (24 - 8 * i)) & 0xFF;
                out.dst_ip[i] = (v4.dst_ip >> (24 - 8 * i)) & 0xFF;
            }
            out.isIpv4 = true;
            return true;
        },
        [&](const ip::v6::Header& v6) {
            memcpy(out.src_ip, v6.src_ip, 16);
            memcpy(out.dst_ip, v6.dst_ip, 16);
            out.isIpv4 = false;
            return true;
        },
        [&](const arp::Header&) { return false; },
        [&](std::monostate) { return false; },
    }, network);
}

bool FlowTable::setPorts(const net::Packet::TransportHeader transport, FlowKey& out) {
    return std::visit(overload{
        [&](const icmp::Header& h) {
            out.protocol = ip::PROTOCOL_ICMP;
            if (h.type == icmp::TYPE_ECHO_REQUEST || h.type == icmp::TYPE_ECHO_REPLY) {
                out.src_port = h.echo.id;
                out.dst_port = h.echo.id;
            } else {
                out.src_port = static_cast<uint16_t>(h.type << 8) | h.code;
                out.dst_port = 0;
            }
            return true;
        },
        [&](const icmpv6::Header& h) {
            out.protocol = ip::PROTOCOL_ICMPV6;
            if (h.type == icmpv6::TYPE_ECHO_REQUEST || h.type == icmpv6::TYPE_ECHO_REPLY) {
                out.src_port = h.echo.id;
                out.dst_port = h.echo.id;
            } else {
                out.src_port = static_cast<uint16_t>(h.type << 8) | h.code;
                out.dst_port = 0;
            }
            return true;
        },
        [&](const tcp::Header& tcp) { out.src_port = tcp.src_port; out.dst_port = tcp.dst_port; out.protocol = ip::PROTOCOL_TCP; return true; },
        [&](const udp::Header& udp) { out.src_port = udp.src_port; out.dst_port = udp.dst_port; out.protocol = ip::PROTOCOL_UDP; return true; },
        [&](std::monostate) { return false; },
    }, transport);
}

bool FlowTable::isExpired(const Flow& flow, uint64_t ts_us) const {
    if (ts_us < flow.last_seen) return false;
    return (ts_us - flow.last_seen > IDLE_TIMEOUT_US) ||
           (ts_us - flow.first_seen > ACTIVE_TIMEOUT_US);
}

const std::vector<std::pair<const FlowKey*, const FlowTable::Flow*>> FlowTable::allFlows() const {
    std::vector<std::pair<const FlowKey*, const FlowTable::Flow*>> flows;
    flows.reserve(completed_.size() + flows_.size());
    for (const auto& [key, flow] : completed_) flows.emplace_back(&key, &flow);
    for (const auto& [key, flow] : flows_) flows.emplace_back(&key, &flow);
    std::sort(flows.begin(), flows.end(), [](const auto& a, const auto& b) {
        return a.second->totalBytes() > b.second->totalBytes();
    });
    return flows;
}

void FlowTable::flush() {
    for (auto& [key, flow] : flows_) {
        completed_.emplace_back(key, std::move(flow));
    }
    flows_.clear();
}

}