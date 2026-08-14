#include <net/decode/decoder.h>

namespace net {

Decoder::Decoder() : dnsTable_(), appDecoder_(dnsTable_), statsEngine_(flowTable_, appDecoder_, dnsTable_) {}

ParseError Decoder::decode(std::span<const uint8_t>& span, pcap::Capture& capture) {
    capture.pkt.reset();
    if (auto err = decode::decodePacket(span, capture.pkt); err != ParseError::None) {
        return err;
    }

    FlowKey flow_key{};
    bool flow_is_new = false;
    FlowTable::Flow* flow = nullptr;
    if (auto err = flowTable_.addPacket(capture, &flow_key, &flow_is_new, &flow); err != ParseError::None) {
        return err;
    }
    if (flow) {
        if (capture.pkt.isTcp()) {
            appDecoder_.pollFlow(flow_key, *flow, flow_is_new);
        } else if (capture.pkt.isUdp()) {
            appDecoder_.pollDatagram(flow_key, flow->is_reverse, capture.pkt.payload, flow_is_new);
        }
    }

    return ParseError::None;
}

void Decoder::finish() {
    flowTable_.flush();
    appDecoder_.prune(flowTable_);
}

}
