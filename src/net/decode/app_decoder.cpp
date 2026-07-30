#include <net/decode/app_decoder.h>

namespace net {

ParseError AppDecoder::pollFlow(const FlowKey& key, Flow& flow) {
    FlowApplications flowApplications = flows_[key];
    pollStream(key, flow.fwd_tcp, flowApplications.fwd);
    pollStream(key, flow.rev_tcp, flowApplications.rev);
    return ParseError::None;
}

ParseError AppDecoder::pollStream(const FlowKey& key, TcpReassembler& stream, Applications& applications) {
    // TODO
    return ParseError::None;
}

ParseError AppDecoder::pollDatagram(const FlowKey& key, bool is_reverse, std::span<const uint8_t> payload) {
    if (payload.size() == 0) {
        return ParseError::None;
    }

    FlowApplications flowApplications = flows_[key];
    Applications& applications = is_reverse ? flowApplications.rev : flowApplications.fwd;

    // TODO
    return ParseError::None;
}

void AppDecoder::reset(const FlowKey& key) {
    flows_.erase(key);
}

void AppDecoder::prune(const FlowTable& table) {
    for (auto it = flows_.begin(); it != flows_.end();) {
        if (table.flows().find(it->first) == table.flows().end()) {
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
}
}
