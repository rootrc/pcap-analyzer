#include <net/decode/app_decoder.h>

namespace net {

AppDecoder::AppDecoder(DnsTable& dnsTable) : dnsTable_(dnsTable) {}

ParseError AppDecoder::pollFlow(const FlowKey& key, Flow& flow) {
    FlowApplications flowApplications = flows_[key];
    pollStream(key, flow.fwd_tcp, flowApplications.fwd);
    pollStream(key, flow.rev_tcp, flowApplications.rev);
    return ParseError::None;
}

ParseError AppDecoder::pollStream(const FlowKey& key, TcpReassembler& stream, Applications& applications) {
    if (!stream.hasReadableData() || applications.decode_failed) return ParseError::None;

    if (key.src_port == dns::PORT || key.dst_port == dns::PORT) {
        while (true) {
            if (stream.available() < 2) break;
            uint16_t msg_len = static_cast<uint16_t>((stream.peek().data()[0] << 8) | stream.peek().data()[1]);
            if (stream.available() < 2u + msg_len) break;

            std::span<const uint8_t> msg{stream.peek().data() + 2, msg_len};
            dns::Header header{};
            if (dns::parse(msg, header, Endian::Big) != ParseError::None) {
                applications.decode_failed = true;
                break;
            }
            dnsTable_.record(header);
            applications.dns_messages.push_back(std::move(header));
            stream.consume(2 + msg_len);
        }
    }
    return ParseError::None;
}

ParseError AppDecoder::pollDatagram(const FlowKey& key, bool is_reverse, std::span<const uint8_t> payload) {
    if (payload.size() == 0) return ParseError::None;

    FlowApplications& flowApplications = flows_[key];
    Applications& applications = is_reverse ? flowApplications.rev : flowApplications.fwd;

    if (applications.decode_failed) return ParseError::None;

    if (key.src_port == dns::PORT || key.dst_port == dns::PORT) {
        dns::Header header{};
        if (dns::parse(payload, header, Endian::Big) != ParseError::None) {
            applications.decode_failed = true;
            return ParseError::None;
        }
        dnsTable_.record(header);
        applications.dns_messages.push_back(std::move(header));
    }
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

const Applications* AppDecoder::getApplications(const FlowKey& key, bool is_reverse) const {
    auto it = flows_.find(key);
    if (it == flows_.end()) {
        return nullptr;
    }
    return is_reverse ? &it->second.rev : &it->second.fwd;
}

}
