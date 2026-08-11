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
    if (auto err = flowTable_.addPacket(capture, &flow_key, &flow_is_new); err != ParseError::None) {
        return err;
    }
    if (flow_is_new) {
        appDecoder_.reset(flow_key);
    }

    if (auto it = flowTable_.flows().find(flow_key); it != flowTable_.flows().end()) {
        if (capture.pkt.isTcp()) {
            appDecoder_.pollFlow(flow_key, it->second);
        } else if (capture.pkt.isUdp()) {
            appDecoder_.pollDatagram(flow_key, it->second.is_reverse, capture.pkt.payload);
        }
    }

    return ParseError::None;
}

void Decoder::finish() {
    flowTable_.flush();
    appDecoder_.prune(flowTable_);
}

}
