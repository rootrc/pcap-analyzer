#include <net/decode/decoder.h>

namespace net {

Decoder::Decoder(Benchmark& benchmark, size_t print_limit, bool verify_checksum, uint64_t flow_active_timeout_us, uint64_t flow_idle_timeout_us)
    : benchmark_(benchmark), flowTable_(flow_active_timeout_us, flow_idle_timeout_us), dnsTable_(), appDecoder_(dnsTable_), statsEngine_(flowTable_, appDecoder_, dnsTable_, benchmark, print_limit), verify_checksum_(verify_checksum) {}

ParseError Decoder::decode(std::span<const uint8_t>& span, pcap::Capture& capture) {
    capture.pkt.reset();

    benchmark_.start(Benchmark::Phase::DecodePacket);
    ParseError decode_err = decode::decodePacket(span, capture.pkt, verify_checksum_);
    benchmark_.stop(Benchmark::Phase::DecodePacket);
    if (decode_err != ParseError::None) {
        return decode_err;
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
