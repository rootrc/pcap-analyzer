#pragma once

#include <net/analysis/benchmark.h>
#include <net/analysis/dns_table.h>
#include <net/analysis/stats_engine.h>
#include <net/capture/capture.h>
#include <net/decode/packet.h>
#include <net/decode/app_decoder.h>
#include <net/decode/packet_decoder.h>
#include <net/flow/flow_table.h>

namespace net {

class Decoder {
public:
    struct Config {
        size_t print_limit = 0;
        bool verify_checksum = true;
        uint64_t flow_active_timeout_us = 0;
        uint64_t flow_idle_timeout_us = FlowTable::DEFAULT_IDLE_TIMEOUT_US;
        FlowKey filter{};
    };
    Decoder(Benchmark& benchmark, Config config);
    ParseError decode(std::span<const uint8_t>& span, pcap::Capture& capture);

    void finish();

    uint64_t decoded() const {return decoded_; };
    const FlowTable& flowTable() const { return flowTable_; }
    const AppDecoder& appDecoder() const { return appDecoder_; }
    const DnsTable& dnsTable() const { return dnsTable_; }
    const StatsEngine& statsEngine() const { return statsEngine_; }
private:
    Benchmark& benchmark_;
    FlowTable flowTable_;
    DnsTable dnsTable_;
    AppDecoder appDecoder_;
    StatsEngine statsEngine_;

    Config config_;
    uint64_t decoded_ = 0;
};

}
