#include <net/decode/app_decoder.h>

namespace net {

AppDecoder::AppDecoder(DnsTable& dnsTable) : dnsTable_(dnsTable) {}

ParseError AppDecoder::pollFlow(const FlowKey& key, FlowTable::Flow& flow, bool flow_is_new) {
    FlowApplications& flowApplications = flows_[key];
    if (flow_is_new) flowApplications = FlowApplications{};
    if (flow.is_reverse) {
        pollStream(key, flow.rev_tcp, flowApplications.rev, flowApplications.fwd);
    } else {
        pollStream(key, flow.fwd_tcp, flowApplications.fwd, flowApplications.rev);
    }
    return ParseError::None;
}

ParseError AppDecoder::pollStream(const FlowKey& key, TcpReassembler& stream, Applications& applications, Applications& peer_state) {
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
    } else if (key.src_port == http::PORT || key.dst_port == http::PORT) {
        while (true) {
            if (applications.http_body_until_close) {
                stream.consume(stream.available());
                break;
            }
            std::span<const uint8_t> span = stream.peek();
            const size_t start_size = span.size();

            http::Header header{};
            ParseError err = http::parse(span, header);
            if (err == ParseError::UnexpectedEof) {
                if (stream.available() > MAX_HTTP_HEADER_BYTES) {
                    applications.decode_failed = true;
                }
                break;
            } else if (err != ParseError::None) {
                applications.decode_failed = true;
                break;
            }

            bool head_response = false;
            if (header.isResponse() && header.status_code >= 200 &&
                !peer_state.pending_head_requests.empty()) {
                head_response = peer_state.pending_head_requests.front();
                peer_state.pending_head_requests.pop_front();
            }

            bool body_incomplete = false;
            if (header.bodyForbidden() || head_response) {

            } else if (header.chunked) {
                span = span.subspan(applications.http_chunk_prefix);
                size_t validated = 0;
                ParseError body_err = http::parseChunkedBody(span, nullptr, &validated);
                if (body_err == ParseError::UnexpectedEof) {
                    applications.http_chunk_prefix += validated;
                    body_incomplete = true;
                } else if (body_err != ParseError::None) {
                    applications.decode_failed = true;
                    break;
                } else {
                    applications.http_chunk_prefix = 0;
                }
            } else if (header.has_content_length) {
                if (span.size() < header.content_length) {
                    body_incomplete = true;
                } else {
                    span = span.subspan(static_cast<size_t>(header.content_length));
                }
            }  else if (header.isResponse()) {
                applications.http_body_until_close = true;
            }

            if (body_incomplete) {
                if (stream.available() > MAX_HTTP_MESSAGE_BYTES) {
                    applications.decode_failed = true;
                }
                break;
            }

            if (header.isRequest() && applications.pending_head_requests.size() < MAX_PENDING_REQUESTS) {
                applications.pending_head_requests.push_back(header.method == "HEAD");
            }

            applications.http_messages.push_back(std::move(header));
            stream.consume(start_size - span.size());
        }
    }
    return ParseError::None;
}

ParseError AppDecoder::pollDatagram(const FlowKey& key, bool is_reverse, std::span<const uint8_t> payload, bool flow_is_new) {
    if (payload.size() == 0) return ParseError::None;

    FlowApplications& flowApplications = flows_[key];
    if (flow_is_new) flowApplications = FlowApplications{};
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
