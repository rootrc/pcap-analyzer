#pragma once

#include <net/analysis/dns_table.h>
#include <net/analysis/stats_engine.h>
#include <net/capture/capture.h>
#include <net/capture/packet.h>
#include <net/decode/app_decoder.h>
#include <net/decode/pkt_decoder.h>
#include <net/flow/flow_tracker.h>

namespace net {

class Decoder {
public:
    Decoder(size_t print_limit_);
    ParseError decode(std::span<const uint8_t>& span, pcap::Capture& capture);

    void finish();

    uint64_t decoded() const {return decoded_; };
    const FlowTable& flowTable() const { return flowTable_; }
    const AppDecoder& appDecoder() const { return appDecoder_; }
    const DnsTable& dnsTable() const { return dnsTable_; }
    const StatsEngine& statsEngine() const { return statsEngine_; }
private:
    FlowTable flowTable_;
    DnsTable dnsTable_;
    AppDecoder appDecoder_;
    StatsEngine statsEngine_;

    uint64_t decoded_ = 0;
};

}
