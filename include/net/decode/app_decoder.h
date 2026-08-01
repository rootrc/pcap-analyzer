#pragma once

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
    ParseError pollFlow(const FlowKey& key, Flow& flow);
    ParseError pollDatagram(const FlowKey& key, bool is_reverse, std::span<const uint8_t> payload);
    void reset(const FlowKey& key);
    void prune(const FlowTable& table);
    const Applications* getApplications(const FlowKey& key, bool is_reverse) const;
private:
    struct FlowApplications {
        Applications fwd;
        Applications rev;
    };

    std::unordered_map<FlowKey, FlowApplications, FlowKeyHash> flows_;

    ParseError pollStream(const FlowKey& key, TcpReassembler& stream, Applications& decoder_state);
};

}
