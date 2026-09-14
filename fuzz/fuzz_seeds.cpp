#include <net/capture/pcap.h>
#include <net/decode/packet.h>
#include <net/decode/packet_decoder.h>
#include <net/flow/flow_key.h>
#include <net/flow/flow_table.h>
#include <net/protocols/protocols.h>
#include <net/util/text.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <vector>

using namespace net;

namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;

namespace {

const fs::path SOURCE_DIR = PCAP_ANALYZER_SOURCE_DIR;

constexpr std::string_view BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

constexpr uint8_t CHECKSUMS_ON = 0x01;
constexpr uint8_t CHECKSUMS_OFF = 0x00;

constexpr size_t MAX_PACKET_SEED_LEN = 1600;
constexpr size_t MAX_HTTP_SEED_LEN = 2048;
constexpr size_t MAX_FLOW_PACKETS = 40;
constexpr size_t MAX_FLOW_SEED_LEN = 64 * 1024;
constexpr size_t CAPTURE_HEAD_PACKETS = 32;
constexpr size_t PCAP_HEADER_SEED_PACKETS = 4;
constexpr uint64_t MAX_PER_OPTION = 1000;

struct Seed {
    std::string target;
    std::string name;
    Bytes bytes;

    bool operator<(const Seed& o) const { return std::tie(target, name, bytes) < std::tie(o.target, o.name, o.bytes); }
};

std::string encodeBase64(const Bytes& bytes) {
    std::string out;
    out.reserve((bytes.size() + 2) / 3 * 4);
    for (size_t i = 0; i < bytes.size(); i += 3) {
        const size_t n = std::min<size_t>(3, bytes.size() - i);
        uint32_t bits = static_cast<uint32_t>(bytes[i]) << 16;
        if (n > 1) bits |= static_cast<uint32_t>(bytes[i + 1]) << 8;
        if (n > 2) bits |= bytes[i + 2];
        out.push_back(BASE64_ALPHABET[(bits >> 18) & 0x3F]);
        out.push_back(BASE64_ALPHABET[(bits >> 12) & 0x3F]);
        out.push_back(n > 1 ? BASE64_ALPHABET[(bits >> 6) & 0x3F] : '=');
        out.push_back(n > 2 ? BASE64_ALPHABET[bits & 0x3F] : '=');
    }
    return out;
}

std::optional<Bytes> decodeBase64(std::string_view text) {
    static const std::array<int8_t, 256> table = [] {
        std::array<int8_t, 256> t{};
        t.fill(-1);
        for (size_t i = 0; i < BASE64_ALPHABET.size(); ++i) {
            t[static_cast<uint8_t>(BASE64_ALPHABET[i])] = static_cast<int8_t>(i);
        }
        return t;
    }();

    if (text.size() % 4 != 0) return std::nullopt;
    Bytes out;
    out.reserve(text.size() / 4 * 3);
    for (size_t i = 0; i < text.size(); i += 4) {
        uint32_t bits = 0;
        int padding = 0;
        for (size_t j = 0; j < 4; ++j) {
            const char c = text[i + j];
            if (c == '=' && i + 4 == text.size() && j >= 2) {
                ++padding;
                bits <<= 6;
                continue;
            }
            const int8_t v = table[static_cast<uint8_t>(c)];
            if (v < 0 || padding) return std::nullopt;
            bits = (bits << 6) | static_cast<uint32_t>(v);
        }
        out.push_back(static_cast<uint8_t>(bits >> 16));
        if (padding < 2) out.push_back(static_cast<uint8_t>(bits >> 8));
        if (padding < 1) out.push_back(static_cast<uint8_t>(bits));
    }
    return out;
}

std::string forEachSeed(const fs::path& path, const std::function<void(Seed&&)>& on_seed) {
    std::ifstream in(path);
    if (!in) return path.string() + ": cannot open seeds file";

    std::string line;
    for (size_t lineno = 1; std::getline(in, line); ++lineno) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;

        const std::string where = path.string() + ':' + std::to_string(lineno) + ": ";
        std::istringstream fields(line);
        std::string target, name, encoded, extra;
        if (!(fields >> target >> name >> encoded) || (fields >> extra)) {
            return where + "expected '<target> <name> <base64>'";
        }
        std::optional<Bytes> bytes = decodeBase64(encoded);
        if (!bytes) return where + "invalid base64 for seed '" + name + "'";
        on_seed(Seed{std::move(target), std::move(name), std::move(*bytes)});
    }
    return {};
}

void put16(Bytes& b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v >> 8));
    b.push_back(static_cast<uint8_t>(v));
}

void put32(Bytes& b, uint32_t v) {
    put16(b, static_cast<uint16_t>(v >> 16));
    put16(b, static_cast<uint16_t>(v));
}

void append(Bytes& b, std::span<const uint8_t> more) { b.insert(b.end(), more.begin(), more.end()); }
void append(Bytes& b, std::string_view more) { b.insert(b.end(), more.begin(), more.end()); }

Bytes join(std::initializer_list<Bytes> parts) {
    Bytes b;
    for (const Bytes& part : parts) append(b, part);
    return b;
}

std::string lowercase(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) out.push_back(static_cast<char>(std::tolower(c)));
    return out;
}

std::string seedName(std::string_view prefix, std::span<const uint8_t> blob) {
    uint32_t h = 2166136261u;
    for (uint8_t c : blob) {
        h ^= c;
        h *= 16777619u;
    }
    char suffix[9];
    std::snprintf(suffix, sizeof(suffix), "%08x", h);
    return std::string(prefix) + '-' + suffix;
}

struct Record {
    Bytes header;
    Bytes frame;
};

struct Capture {
    Bytes file_header;
    pcap::FileHeader parsed;
    std::vector<Record> records;
};

std::optional<Capture> readCapture(const fs::path& path, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = path.string() + ": cannot open capture";
        return std::nullopt;
    }
    const Bytes data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    Capture capture;
    std::span<const uint8_t> span{data};
    Endian endian = Endian::Little;
    if (auto err = pcap::parse(span, capture.parsed, endian); err != ParseError::None) {
        error = path.string() + ": not a supported classic pcap (" + std::string(toString(err)) + ')';
        return std::nullopt;
    }
    capture.file_header.assign(data.begin(), data.begin() + pcap::FILE_HEADER_LEN);

    while (span.size() >= pcap::PACKET_HEADER_LEN) {
        const std::span<const uint8_t> raw_header = span.first(pcap::PACKET_HEADER_LEN);
        pcap::PacketHeader header{};
        if (pcap::parse(span, header, endian) != ParseError::None || span.size() < header.incl_len) break;
        capture.records.push_back({Bytes(raw_header.begin(), raw_header.end()),
                                   Bytes(span.begin(), span.begin() + header.incl_len)});
        span = span.subspan(header.incl_len);
    }
    return capture;
}

std::string packetKind(const Packet& pkt) {
    std::string kind;
    for (size_t i = 0; i < pkt.vlan().size(); ++i) kind += "vlan-";
    if (pkt.isArp()) return kind + "arp";
    kind += pkt.isIpv4() ? "ipv4" : "ipv6";
    if (pkt.isTcp()) return kind + "-tcp";
    if (pkt.isUdp()) return kind + "-udp";
    if (pkt.isIcmp()) return kind + "-icmp";
    return kind + "-icmpv6";
}

std::vector<std::pair<std::string, Bytes>> syntheticFrames() {
    const Bytes mac = {0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02};
    const Bytes src_ip4 = {10, 0, 0, 1};
    const Bytes dst_ip4 = {10, 0, 0, 2};
    const Bytes src_ip6 = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
    const Bytes dst_ip6 = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};

    Bytes tcp;
    put16(tcp, 49152);
    put16(tcp, http::PORT);
    put32(tcp, 1);
    put32(tcp, 0);
    tcp.push_back(static_cast<uint8_t>(tcp::MIN_DATA_OFFSET << 4));
    tcp.push_back(0x18);
    put16(tcp, 65535);
    put16(tcp, 0);
    put16(tcp, 0);
    append(tcp, "GET / HTTP/1.1\r\nHost: a\r\n\r\n");

    Bytes dns_query;
    put16(dns_query, 0x1234);
    put16(dns_query, 0x0100);
    put16(dns_query, 1);
    put16(dns_query, 0);
    put16(dns_query, 0);
    put16(dns_query, 0);
    append(dns_query, Bytes{0x01, 'a', 0x03, 'n', 'e', 't', 0x00});
    put16(dns_query, dns::TYPE_A);
    put16(dns_query, dns::CLASS_IN);

    Bytes udp;
    put16(udp, 53000);
    put16(udp, dns::PORT);
    put16(udp, static_cast<uint16_t>(udp::HEADER_LEN + dns_query.size()));
    put16(udp, 0);
    append(udp, dns_query);

    Bytes icmp6 = {icmpv6::TYPE_ECHO_REQUEST, 0};
    put16(icmp6, 0);
    put16(icmp6, 1);
    put16(icmp6, 1);
    append(icmp6, "ping");

    auto ipv4 = [&](uint8_t protocol, const Bytes& l4) {
        Bytes b = {static_cast<uint8_t>((ip::v4::SUPPORTED_VERSION << 4) | ip::v4::MIN_IHL), 0};
        put16(b, static_cast<uint16_t>(ip::v4::MIN_HEADER_LEN + l4.size()));
        put16(b, 1);
        put16(b, 0x4000);
        b.push_back(64);
        b.push_back(protocol);
        put16(b, 0);
        return join({b, src_ip4, dst_ip4, l4});
    };
    auto ipv6 = [&](uint8_t next_header, const Bytes& l4) {
        Bytes b;
        put32(b, static_cast<uint32_t>(ip::v6::SUPPORTED_VERSION) << 28);
        put16(b, static_cast<uint16_t>(l4.size()));
        b.push_back(next_header);
        b.push_back(64);
        return join({b, src_ip6, dst_ip6, l4});
    };
    auto vlanTag = [](uint16_t tpid, uint16_t vid, const Bytes& inner) {
        Bytes b;
        put16(b, tpid);
        put16(b, vid);
        return join({b, inner});
    };
    auto ethertype = [](uint16_t type) {
        Bytes b;
        put16(b, type);
        return b;
    };

    const Bytes hop_by_hop = {ip::PROTOCOL_TCP, 0, 1, 4, 0, 0, 0, 0};
    const Bytes routing = join({{ip::PROTOCOL_UDP, 2, 0, 1, 0, 0, 0, 0}, dst_ip6});
    const Bytes fragment = {ip::PROTOCOL_TCP, 0, 0, 1, 0, 0, 0, 42};
    const Bytes type_ip4 = ethertype(ethernet::ETHERTYPE_IPV4);
    const Bytes type_ip6 = ethertype(ethernet::ETHERTYPE_IPV6);

    return {
        {"vlan-ipv4-tcp", join({mac, vlanTag(ethernet::ETHERTYPE_VLAN, 100, type_ip4), ipv4(ip::PROTOCOL_TCP, tcp)})},
        {"qinq-ipv4-udp", join({mac, vlanTag(ethernet::ETHERTYPE_VLAN_QQ, 200, vlanTag(ethernet::ETHERTYPE_VLAN, 100, type_ip4)),
                                ipv4(ip::PROTOCOL_UDP, udp)})},
        {"ipv6-tcp", join({mac, type_ip6, ipv6(ip::PROTOCOL_TCP, tcp)})},
        {"ipv6-udp", join({mac, type_ip6, ipv6(ip::PROTOCOL_UDP, udp)})},
        {"ipv6-icmpv6", join({mac, type_ip6, ipv6(ip::PROTOCOL_ICMPV6, icmp6)})},
        {"ipv6-hopbyhop-tcp", join({mac, type_ip6, ipv6(ip::PROTOCOL_HOPOPT, join({hop_by_hop, tcp}))})},
        {"ipv6-routing-udp", join({mac, type_ip6, ipv6(ip::PROTOCOL_IPV6_ROUTE, join({routing, udp}))})},
        {"ipv6-fragment-tcp", join({mac, type_ip6, ipv6(ip::PROTOCOL_IPV6_FRAG, join({fragment, tcp}))})},
    };
}

bool hasPort(const FlowKey& key, uint16_t port) { return key.src_port == port || key.dst_port == port; }

int generate(const fs::path& pcap_path, const fs::path& out_path, size_t per_payload, size_t per_kind) {
    std::string error;
    const std::optional<Capture> capture = readCapture(pcap_path, error);
    if (!capture) {
        std::cerr << error << '\n';
        return 1;
    }

    std::vector<Seed> seeds;
    std::map<std::string, size_t> kind_counts;
    std::vector<Bytes> dns_payloads;
    std::vector<Bytes> http_payloads;
    std::unordered_map<FlowKey, std::vector<const Record*>, FlowKeyHash> flows;
    std::vector<FlowKey> flow_order;

    for (const Record& record : capture->records) {
        Packet pkt;
        pkt.setDatatypeFromLinktype(capture->parsed.linktype);
        std::span<const uint8_t> span{record.frame};
        if (decode::decodePacket(span, pkt, false) != ParseError::None) continue;

        const std::string kind = packetKind(pkt);
        if (record.frame.size() <= MAX_PACKET_SEED_LEN && kind_counts[kind] < per_kind) {
            ++kind_counts[kind];
            Bytes seed = {CHECKSUMS_ON};
            append(seed, record.frame);
            seeds.push_back({"fuzz_packet", seedName(kind, record.frame), std::move(seed)});
        }

        FlowKey key{};
        if (FlowTable::keyFromPacket(pkt, key) != ParseError::None) continue;
        const Bytes payload(pkt.payload.begin(), pkt.payload.end());

        if (pkt.isUdp() && hasPort(key, dns::PORT) && dns_payloads.size() < per_payload &&
            std::find(dns_payloads.begin(), dns_payloads.end(), payload) == dns_payloads.end()) {
            std::span<const uint8_t> msg{payload};
            dns::Header header{};
            if (dns::parse(msg, header, Endian::Big) == ParseError::None) {
                dns_payloads.push_back(payload);
                seeds.push_back({"fuzz_dns", seedName(header.isResponse() ? "response" : "query", payload), payload});
            }
        }

        if (pkt.isTcp() && hasPort(key, http::PORT) && http_payloads.size() < per_payload) {
            std::span<const uint8_t> msg{payload};
            http::Header header{};
            Bytes head(payload.begin(), payload.begin() + std::min(payload.size(), MAX_HTTP_SEED_LEN));
            if (http::parse(msg, header) == ParseError::None &&
                std::find(http_payloads.begin(), http_payloads.end(), head) == http_payloads.end()) {
                const std::string label = header.isResponse() ? "response" : lowercase(header.method);
                seeds.push_back({"fuzz_http", seedName(label, head), head});
                http_payloads.push_back(std::move(head));
            }
        }

        if ((pkt.isTcp() || pkt.isUdp()) && (hasPort(key, dns::PORT) || hasPort(key, http::PORT))) {
            key.normalize();
            auto [it, inserted] = flows.try_emplace(key);
            if (inserted) flow_order.push_back(key);
            it->second.push_back(&record);
        }
    }

    for (const auto& [name, frame] : syntheticFrames()) {
        Packet pkt;
        pkt.setDatatypeFromLinktype(pcap::LINKTYPE_ETHERNET);
        std::span<const uint8_t> span{frame};
        const ParseError err = decode::decodePacket(span, pkt, false);
        if (err != ParseError::None && err != ParseError::UnsupportedTransportType) {
            std::cerr << "synthetic frame '" << name << "' does not decode (" << err << "); fix syntheticFrames()\n";
            return 1;
        }
        Bytes seed = {CHECKSUMS_OFF};
        append(seed, frame);
        seeds.push_back({"fuzz_packet", name, std::move(seed)});
    }

    auto pcapBlob = [&](const std::vector<const Record*>& records) {
        Bytes blob = capture->file_header;
        for (const Record* record : records) {
            append(blob, record->header);
            append(blob, record->frame);
        }
        return blob;
    };
    auto firstRecords = [&](size_t count) {
        std::vector<const Record*> out;
        for (size_t i = 0; i < std::min(count, capture->records.size()); ++i) out.push_back(&capture->records[i]);
        return out;
    };

    seeds.push_back({"fuzz_capture", "head-" + std::to_string(CAPTURE_HEAD_PACKETS) + "-packets",
                     pcapBlob(firstRecords(CAPTURE_HEAD_PACKETS))});
    bool have_http_flow = false;
    bool have_dns_flow = false;
    for (const FlowKey& key : flow_order) {
        const std::vector<const Record*>& records = flows.at(key);
        const bool http_flow = key.protocol == ip::PROTOCOL_TCP && hasPort(key, http::PORT);
        const bool dns_flow = key.protocol == ip::PROTOCOL_UDP && hasPort(key, dns::PORT);
        if (!(http_flow && !have_http_flow) && !(dns_flow && !have_dns_flow)) continue;
        if (records.size() > MAX_FLOW_PACKETS) continue;
        Bytes blob = pcapBlob(records);
        if (blob.size() > MAX_FLOW_SEED_LEN) continue;
        (http_flow ? have_http_flow : have_dns_flow) = true;
        seeds.push_back({"fuzz_capture", http_flow ? "http-flow" : "dns-flow", std::move(blob)});
    }

    seeds.push_back({"fuzz_pcap_header", "head-" + std::to_string(PCAP_HEADER_SEED_PACKETS) + "-packets",
                     pcapBlob(firstRecords(PCAP_HEADER_SEED_PACKETS))});

    for (const auto& [name, text] : {std::pair{"v4-text", "10.0.0.1"}, std::pair{"v6-text", "2001:db8::1"}}) {
        Bytes bytes;
        append(bytes, text);
        seeds.push_back({"fuzz_address", name, std::move(bytes)});
    }

    std::sort(seeds.begin(), seeds.end());

    std::ofstream file(out_path, std::ios::binary);
    std::map<std::string, std::pair<size_t, size_t>> counts;
    for (const Seed& seed : seeds) {
        file << seed.target << ' ' << seed.name << ' ' << encodeBase64(seed.bytes) << '\n';
        auto& [count, bytes] = counts[seed.target];
        ++count;
        bytes += seed.bytes.size();
    }
    file.close();
    if (!file) {
        std::cerr << out_path.string() << ": cannot write\n";
        return 1;
    }

    for (const auto& [target, count] : counts) {
        std::cout << target << ": " << count.first << " seeds, " << count.second << " bytes\n";
    }
    std::cout << "wrote " << out_path.string() << " (" << fs::file_size(out_path) << " bytes)\n";
    return 0;
}

int unpack(const fs::path& seeds_path, const fs::path& out_dir, const std::string& only_target) {
    size_t written = 0;
    std::string write_error;
    std::string error = forEachSeed(seeds_path, [&](Seed&& seed) {
        if (!write_error.empty() || (!only_target.empty() && seed.target != only_target)) return;
        const fs::path dir = out_dir / seed.target;
        std::error_code ec;
        fs::create_directories(dir, ec);
        if (ec) {
            write_error = dir.string() + ": " + ec.message();
            return;
        }
        std::ofstream file(dir / seed.name, std::ios::binary);
        if (!file.write(reinterpret_cast<const char*>(seed.bytes.data()), static_cast<std::streamsize>(seed.bytes.size()))) {
            write_error = (dir / seed.name).string() + ": cannot write";
            return;
        }
        ++written;
    });
    if (error.empty()) error = write_error;
    if (!error.empty()) {
        std::cerr << error << '\n';
        return 1;
    }
    if (written == 0) {
        std::cerr << seeds_path.string() << ": no seeds for " << (only_target.empty() ? "any target" : only_target) << '\n';
        return 1;
    }
    std::cout << "unpacked " << written << " seeds into " << out_dir.string() << '\n';
    return 0;
}

void printUsage(std::ostream& os) {
    os <<
        "usage: fuzz_seeds [generate] [capture.pcap] [--out FILE] [--per-payload N] [--per-kind N]\n"
        "       fuzz_seeds unpack DIR [--target NAME] [--seeds FILE]\n";
}

}

int main(int argc, char** argv) {
    std::vector<std::string_view> args(argv + 1, argv + argc);
    if (!args.empty() && (args[0] == "-h" || args[0] == "--help")) {
        printUsage(std::cout);
        return 0;
    }
    const bool unpacking = !args.empty() && args[0] == "unpack";
    if (!args.empty() && (args[0] == "unpack" || args[0] == "generate")) args.erase(args.begin());

    const std::vector<std::string_view> known = unpacking
        ? std::vector<std::string_view>{"--target", "--seeds"}
        : std::vector<std::string_view>{"--out", "--per-payload", "--per-kind"};
    std::vector<std::string_view> positional;
    std::map<std::string_view, std::string_view> options;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i].substr(0, 2) != "--") {
            positional.push_back(args[i]);
            continue;
        }
        if (std::find(known.begin(), known.end(), args[i]) == known.end()) {
            std::cerr << "fuzz_seeds: unknown option " << args[i] << '\n';
            printUsage(std::cerr);
            return 2;
        }
        if (i + 1 >= args.size()) {
            std::cerr << "fuzz_seeds: " << args[i] << " requires a value\n";
            return 2;
        }
        options[args[i]] = args[i + 1];
        ++i;
    }
    auto option = [&](std::string_view name, const fs::path& fallback) {
        auto it = options.find(name);
        return it == options.end() ? fallback : fs::path(it->second);
    };
    const fs::path default_seeds = SOURCE_DIR / "fuzz" / "seeds.txt";

    if (unpacking) {
        if (positional.size() != 1) {
            printUsage(std::cerr);
            return 2;
        }
        auto target = options.find("--target");
        return unpack(option("--seeds", default_seeds), positional[0],
                      target == options.end() ? std::string() : std::string(target->second));
    }

    if (positional.size() > 1) {
        printUsage(std::cerr);
        return 2;
    }
    uint64_t per_payload = 4;
    uint64_t per_kind = 1;
    for (auto [name, value] : {std::pair{"--per-payload", &per_payload}, std::pair{"--per-kind", &per_kind}}) {
        auto it = options.find(name);
        if (it != options.end() && !util::parseUint(it->second, *value, MAX_PER_OPTION)) {
            std::cerr << "fuzz_seeds: " << name << " takes a number from 0 to " << MAX_PER_OPTION << '\n';
            return 2;
        }
    }
    const fs::path capture = positional.empty() ? SOURCE_DIR / "samples" / "smallFlows.pcap" : fs::path(positional[0]);
    return generate(capture, option("--out", default_seeds), per_payload, per_kind);
}
