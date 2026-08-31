#include <net/analysis/stats_engine.h>
#include <net/util/string.h>

#include <algorithm>
#include <iomanip>
#include <map>
#include <sstream>
#include <unordered_map>
#include <vector>

namespace net {

namespace {

void printBytes(std::ostream& os, uint64_t bytes) {
    if (bytes > 10 * (1 << 20)) {
        os << (bytes >> 20) << "MB";
    } else if (bytes > 10 * (1 << 10)) {
        os << (bytes >> 10) << "KB";
    } else {
        os << bytes << 'B';
    }
}

void printRate(std::ostream& os, double bps) {
    if (bps >= 1e9) {
        os << std::fixed << std::setprecision(2) << (bps / 1e9) << "Gbps";
    } else if (bps >= 1e6) {
        os << std::fixed << std::setprecision(2) << (bps / 1e6) << "Mbps";
    } else if (bps >= 1e3) {
        os << std::fixed << std::setprecision(2) << (bps / 1e3) << "Kbps";
    } else {
        os << std::fixed << std::setprecision(2) << bps << "bps";
    }
}

}

StatsEngine::StatsEngine(const FlowTable& flowTable, const AppDecoder& appDecoder, const DnsTable& dnsTable, size_t print_limit_)
    : flowTable_(flowTable), appDecoder_(appDecoder), dnsTable_(dnsTable) {
    print_limit = print_limit_;
}

std::vector<std::pair<const FlowKey*, const FlowTable::Flow*>> StatsEngine::sortedFlowsByBytes() const {
    std::vector<std::pair<const FlowKey*, const FlowTable::Flow*>> sortedFlow;
    sortedFlow.reserve(flowTable_.completed().size() + flowTable_.flows().size());
    for (const auto& [k, f] : flowTable_.completed()) {
        sortedFlow.emplace_back(&k, &f);
    }
    for (const auto& [k, f] : flowTable_.flows()) {
        sortedFlow.emplace_back(&k, &f);
    }
    std::sort(sortedFlow.begin(), sortedFlow.end(), [](const auto& a, const auto& b) { return a.second->totalBytes() > b.second->totalBytes(); });
    return sortedFlow;
}

std::vector<std::pair<uint8_t, uint64_t>> StatsEngine::sortedProtocolsByBytes(std::vector<std::pair<const FlowKey*, const FlowTable::Flow*>> sortedFlow) const {
    std::unordered_map<uint8_t, uint64_t> protocolBytes;
    for (const auto& [kp, fp] : sortedFlow) {
        protocolBytes[kp->protocol] += fp->totalBytes();
    }
    std::vector<std::pair<uint8_t, uint64_t>> sortedProtocols(protocolBytes.begin(), protocolBytes.end());
    std::sort(sortedProtocols.begin(), sortedProtocols.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
    return sortedProtocols;
}

void StatsEngine::printFlow(std::ostream& os, const FlowKey& key, const FlowTable::Flow& flow) const {
   double percent = flow.payloadPercent(flowTable_.total_bytes());
    os << "(";
    (percent > 0.0 && percent < 0.01) ? (os << "<0.01") : (os << percent);
    os << "%)  " << key;
    
    const std::vector<std::string>* src_domains = dnsTable_.domainsFor(key.src_ip, key.isIpv4);
    const std::vector<std::string>* dst_domains = dnsTable_.domainsFor(key.dst_ip, key.isIpv4);
    if ((src_domains && !src_domains->empty()) || (dst_domains && !dst_domains->empty())) {
        os << "  [";
        bool first = true;
        if (src_domains && !src_domains->empty()) {
            os << "src=" << (*src_domains)[0];
            first = false;
        }
        if (dst_domains && !dst_domains->empty()) {
            if (!first) os << ", ";
            os << "dst=" << (*dst_domains)[0];
        }
        os << ']';
    }

    auto printStats = [&](const char* label, const FlowTable::FlowStats& s) {
        if (!s.bytes) return;
        os << "  " << label << '=' << s.packets << "pkts/";
        printBytes(os, s.bytes);
        if (s.packets > 1) {
            os << " avg=" << (s.bytes / s.packets) << "B";
        }
    };
    printStats("fwd", flow.fwd_stats);
    printStats("rev", flow.rev_stats);

    if (key.protocol == ip::PROTOCOL_TCP) {
        os << "  TCP=" << flow.fwd_tcp.state << '/' << flow.rev_tcp.state;
    }

    if (flow.durationUs() && flow.totalPackets() > 1) {
        os << "  rate=";
        double bps = static_cast<double>(flow.totalBytes()) * 8.0 * 1e6 / static_cast<double>(flow.durationUs());
        printRate(os, bps);
    }
    os << '\n';
}

void StatsEngine::printDns(std::ostream& os) const noexcept {
    std::map<std::string, std::vector<std::string>> resolved;
    size_t queries = 0;

    for (const auto& [ip, domains] : dnsTable_.domainsByIp()) {
        std::ostringstream oss;
        if (ip.isIpv4) {
            ip::v4::printIp(oss, ip.ip);
        } else {
            ip::v6::printIp(oss, ip.ip);
        }

        for (const std::string& domain : domains) {
            resolved[domain].push_back(oss.str());
        }
    }

    os << "  queries seen      " << queries << '\n';
    os << "  names resolved    " << resolved.size() << '\n';

    size_t printed = 0;
    for (const auto& [name, addrs] : resolved) {
        if (printed && printed == print_limit) {
            os << "  ... limit reached\n";
            break;
        }
        os << "  " << std::left << std::setw(48) << name << ' ';
        for (size_t i = 0; i < addrs.size(); ++i) {
            if (i) os << ", ";
            os << addrs[i];
        }
        os << '\n';
        ++printed;
    }
    if (resolved.empty()) os << "  (no answers)\n";
    os << '\n';
}

void StatsEngine::printHttp(std::ostream& os) const noexcept {
    size_t printed = 0;
    bool truncated = false;

    for (const auto& [key, flow] : flowTable_.allFlows()) {
        for (bool reverse : {false, true}) {
            const Applications* apps = appDecoder_.getApplications(*key, reverse);
            if (!apps || apps->http_messages.empty()) continue;

            for (const http::Header& msg : apps->http_messages) {
                if (print_limit && printed >= print_limit) {
                    truncated = true;
                    break;
                }
                os << "  " << *key << (reverse ? "  <-  " : "  ->  ");
                if (msg.isRequest()) {
                    os << msg.method << ' ' << msg.target << ' ' << msg.version;
                    if (const std::string* host = msg.fieldValue("Host")) {
                        os << "  Host: " << *host;
                    }
                } else {
                    os << msg.version << ' ' << msg.status_code;
                    if (!msg.reason_phrase.empty()) os << ' ' << msg.reason_phrase;
                    if (const std::string* type = msg.fieldValue("Content-Type")) {
                        os << "  " << *type;
                    }
                }
                if (msg.chunked) {
                    os << "  [chunked]";
                } else if (msg.has_content_length) {
                    os << "  [" << msg.content_length << "B]";
                }
                os << '\n';
                printed++;
            }
            if (truncated) break;
        }
        if (truncated) break;
    }

    if (!printed) os << "  (none)\n";
    if (truncated) os << "  ... limit reached\n";
    os << '\n';
}

std::string StatsEngine::toString() const noexcept {
    std::vector<std::pair<const FlowKey*, const FlowTable::Flow*>> sortedFlow = sortedFlowsByBytes();
    std::vector<std::pair<uint8_t, uint64_t>> sortedProtocols = sortedProtocolsByBytes(sortedFlow);

    std::ostringstream oss;
    auto flags = oss.flags();
    oss << std::fixed << std::setprecision(2)
        << "FlowTable (" << sortedFlow.size() << " flows";
    if (print_limit != 0 && print_limit != sortedFlow.size()) {
        oss << ", showing " << print_limit;
    }
    oss << ")  [";
    for (size_t i = 0; i < sortedProtocols.size(); ++i) {
        if (i) oss << "  ";
        double pct = flowTable_.total_bytes() ? 100.0 * sortedProtocols[i].second / flowTable_.total_bytes() : 0.0;
        oss << ip::protocolName(sortedProtocols[i].first) << ": " << pct << '%';
    }
    oss << "] {\n";
    size_t printed = 0;
    for (const auto& [key, flow] : sortedFlow) {
        if (printed && printed == print_limit) {
            oss << "  ... limit reached\n";
            break;
        }
        oss << "  ";
        printFlow(oss, *key, *flow);
        ++printed;
    }
    oss << "}\n";
    oss.flags(flags);
    return oss.str();
}

std::string StatsEngine::toJson() const noexcept {
    std::vector<std::pair<const FlowKey*, const FlowTable::Flow*>> sortedFlow = sortedFlowsByBytes();
    std::vector<std::pair<uint8_t, uint64_t>> sortedProtocols = sortedProtocolsByBytes(sortedFlow);
    std::ostringstream oss;
    oss << "\"stats_engine\": {\n"
        << "  \"flow_count\": " << sortedFlow.size() << ",\n"
        << "  \"total_bytes\": " << flowTable_.total_bytes() << ",\n"
        << "  \"protocols\": [\n";
    for (size_t i = 0; i < sortedProtocols.size(); ++i) {
        if (i) oss << ", ";
        double pct = flowTable_.total_bytes() ? 100.0 * sortedProtocols[i].second / flowTable_.total_bytes() : 0.0;
        oss << "    {\n"
            << "      \"protocol\": \"" << ip::protocolName(sortedProtocols[i].first) << "\",\n"
            << "      \"bytes\": " << sortedProtocols[i].second << ",\n"
            << "      \"percent\": " << pct << '\n'
            << "    }\n";
    }
    oss << "  ],\n"
        << "  \"flows\": [\n";
    for (size_t i = 0; i < sortedFlow.size(); ++i) {
        if (i) oss << ",\n";
        oss << "    {\n";
        const auto& [key, flow] = sortedFlow[i];
        oss << util::indent(key->toJson(), "      ")
            << "\n    }";
    }
    oss << "\n  ]\n"
        << "}";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const StatsEngine& engine) {
    return os << engine.toString();
}

}