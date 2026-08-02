#pragma once

#include <net/analysis/dns_table.h>
#include <net/capture/capture.h>
#include <net/capture/packet.h>
#include <net/decode/app_decoder.h>
#include <net/decode/pkt_decoder.h>
#include <net/flow/flow_tracker.h>

namespace net {

class Decoder {
public:
    Decoder();
    ParseError decode(std::span<const uint8_t>& span, pcap::Capture& capture);

    void finish();

    const FlowTable& flowTable() const { return flowTable_; }
    const AppDecoder& appDecoder() const { return appDecoder_; }
    const DnsTable& dnsTable() const { return dnsTable_; }
private:
    FlowTable flowTable_;
    DnsTable dnsTable_;
    AppDecoder appDecoder_;
};

}
