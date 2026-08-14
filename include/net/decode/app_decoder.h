#pragma once

#include <net/analysis/dns_table.h>
#include <net/flow/flow_tracker.h>

#include <unordered_map>
#include <vector>

namespace net {

struct Applications {
    bool decode_failed = false;
    std::vector<dns::Header> dns_messages;
};

class AppDecoder {
public:
    explicit AppDecoder(DnsTable& dnsTable);
    ParseError pollFlow(const FlowKey& key, FlowTable::Flow& flow, bool flow_is_new = false);
    ParseError pollDatagram(const FlowKey& key, bool is_reverse, std::span<const uint8_t> payload, bool flow_is_new = false);
    void reset(const FlowKey& key);
    void prune(const FlowTable& table);
    const Applications* getApplications(const FlowKey& key, bool is_reverse) const;
private:
    struct FlowApplications {
        Applications fwd;
        Applications rev;
    };

    std::unordered_map<FlowKey, FlowApplications, FlowKeyHash> flows_;
    DnsTable& dnsTable_;

    ParseError pollStream(const FlowKey& key, TcpReassembler& stream, Applications& decoder_state);
};

}
