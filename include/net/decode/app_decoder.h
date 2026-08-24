#pragma once

#include <net/analysis/dns_table.h>
#include <net/flow/flow_tracker.h>

#include <deque>
#include <unordered_map>
#include <vector>

namespace net {

constexpr size_t MAX_HTTP_HEADER_BYTES = 32 * 1024;
constexpr size_t MAX_HTTP_MESSAGE_BYTES = 8 * 1024 * 1024;
constexpr size_t MAX_PENDING_REQUESTS = 1024;

struct Applications {
    bool decode_failed = false;
    std::vector<dns::Header> dns_messages;
    std::vector<http::Header> http_messages;
    size_t http_chunk_prefix = 0;
    std::deque<bool> pending_head_requests;
    bool http_body_until_close = false;
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

    ParseError pollStream(const FlowKey& key, TcpReassembler& stream, Applications& decoder_state, Applications& peer_state);
};

}
