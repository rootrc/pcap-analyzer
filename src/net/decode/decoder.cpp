#include <net/decode/decoder.h>

namespace net {

Decoder::Decoder(Benchmark& benchmark, Config config)
    : benchmark_(benchmark), flowTable_(config.flow_active_timeout_us, config.flow_idle_timeout_us), dnsTable_(), appDecoder_(dnsTable_), statsEngine_(flowTable_, appDecoder_, dnsTable_, benchmark, config.print_limit), config_(config) {}

ParseError Decoder::decode(std::span<const uint8_t>& span, pcap::Capture& capture) {
    capture.pkt.reset();

    benchmark_.start(Benchmark::Phase::DecodePacket);
    ParseError decode_err = decode::decodePacket(span, capture.pkt, config_.verify_checksum);
    benchmark_.stop(Benchmark::Phase::DecodePacket);
    if (decode_err != ParseError::None) {
        return decode_err;
    }

    if (config_.filter.isNonZero()) {
        FlowKey key{};
        if (FlowTable::keyFromPacket(capture.pkt, key) != ParseError::None || !config_.filter.matches(key)) {
            return ParseError::Filtered;
        }
    }

    FlowKey flow_key{};
    bool flow_is_new = false;
    FlowTable::Flow* flow = nullptr;
    benchmark_.start(Benchmark::Phase::FlowLookup);
    ParseError flow_err = flowTable_.addPacket(capture, &flow_key, &flow_is_new, &flow);
    benchmark_.stop(Benchmark::Phase::FlowLookup);
    if (flow_err != ParseError::None) {
        return flow_err;
    }

    if (flow && capture.pkt.isTcp()) {
        benchmark_.start(Benchmark::Phase::TcpReassembly);
        TcpReassembler& self = flow->is_reverse ? flow->rev_tcp : flow->fwd_tcp;
        TcpReassembler& other = flow->is_reverse ? flow->fwd_tcp : flow->rev_tcp;
        self.onSent(*capture.pkt.tcp(), capture.pkt.payload);
        other.onReceived(*capture.pkt.tcp());
        benchmark_.stop(Benchmark::Phase::TcpReassembly);
    }

    if (flow) {
        benchmark_.start(Benchmark::Phase::AppDecode);
        if (capture.pkt.isTcp()) {
            appDecoder_.pollFlow(flow_key, *flow, flow_is_new);
        } else if (capture.pkt.isUdp()) {
            appDecoder_.pollDatagram(flow_key, *flow, capture.pkt.payload, flow_is_new);
        }
        benchmark_.stop(Benchmark::Phase::AppDecode);
    }
    ++decoded_;

    return ParseError::None;
}

void Decoder::finish() {
    decoded_ = 0;
    flowTable_.flush();
    appDecoder_.prune(flowTable_);
}

}
