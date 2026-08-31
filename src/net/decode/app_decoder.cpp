#include <net/decode/app_decoder.h>

#include <algorithm>
#include <string_view>

namespace net {

namespace {

size_t findHttpResync(std::span<const uint8_t> buf) {
    static constexpr std::string_view markers[] = {
        "HTTP/1.0", "HTTP/1.1",
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
        "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ",
    };
    std::string_view v(reinterpret_cast<const char*>(buf.data()), buf.size());
    size_t best = std::string_view::npos;
    for (std::string_view m : markers) {
        for (size_t p = v.find(m, 1); p != std::string_view::npos; p = v.find(m, p + 1)) {
            if (p >= 2 && v[p - 1] == '\n' && v[p - 2] == '\r') {
                best = std::min(best, p);
                break;
            }
        }
    }
    return best;
}

}

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

bool AppDecoder::resyncHttp(TcpReassembler& stream, Applications& applications) {
    applications.http_chunk_prefix = 0;
    applications.http_body_until_close = false;

    size_t at = findHttpResync(stream.peek());
    if (at != std::string_view::npos) {
        applications.decode_failures++;
        stream.consume(at);
        return true;
    }
    if (stream.available() > MAX_HTTP_MESSAGE_BYTES) {
        applications.decode_failures++;
        stream.consume(stream.available());
        return true;
    }
    return false;
}

ParseError AppDecoder::pollStream(const FlowKey& key, TcpReassembler& stream, Applications& applications, Applications& peer_state) {
    if (!stream.hasReadableData()) return ParseError::None;

    if (key.src_port == dns::PORT || key.dst_port == dns::PORT) {
        while (true) {
            if (stream.available() < 2) break;
            uint16_t msg_len = static_cast<uint16_t>((stream.peek().data()[0] << 8) | stream.peek().data()[1]);
            if (stream.available() < 2u + msg_len) break;

            std::span<const uint8_t> msg{stream.peek().data() + 2, msg_len};
            dns::Header header{};
            if (dns::parse(msg, header, Endian::Big) != ParseError::None) {
                applications.decode_failures++;
                stream.consume(2u + msg_len);
                continue;
            }
            dnsTable_.record(header);
            applications.dns_messages.push_back(std::move(header));
            stream.consume(2u + msg_len);
        }
    } else if (key.src_port == http::PORT || key.dst_port == http::PORT) {
        while (true) {
            if (applications.http_skip > 0) {
                size_t n = std::min(applications.http_skip, stream.available());
                stream.consume(n);
                applications.http_skip -= n;
                if (applications.http_skip > 0) break;
                continue;
            }

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
                    if (!resyncHttp(stream, applications)) break;
                    continue;
                }
                break;
            } else if (err != ParseError::None) {
                if (!resyncHttp(stream, applications)) break;
                continue;
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
                    if (!resyncHttp(stream, applications)) break;
                    continue;
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
                    if (header.has_content_length && !header.chunked) {
                        size_t header_bytes = start_size - span.size();
                        size_t body_len = static_cast<size_t>(header.content_length);
                        if (header.isRequest() &&
                            applications.pending_head_requests.size() < MAX_PENDING_REQUESTS) {
                            applications.pending_head_requests.push_back(header.method == "HEAD");
                        }
                        applications.http_messages.push_back(std::move(header));
                        stream.consume(header_bytes);
                        applications.http_skip = body_len;
                        applications.decode_failures++;
                        continue;
                    }
                    if (!resyncHttp(stream, applications)) break;
                    continue;
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

    if (key.src_port == dns::PORT || key.dst_port == dns::PORT) {
        dns::Header header{};
        if (dns::parse(payload, header, Endian::Big) != ParseError::None) {
            applications.decode_failures++;
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
