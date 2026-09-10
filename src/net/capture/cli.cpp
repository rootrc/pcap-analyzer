#include <net/capture/cli.h>
#include <net/protocols/ip.h>
#include <net/protocols/ipv4.h>
#include <net/protocols/ipv6.h>
#include <net/util/text.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <map>

using namespace net;

namespace {

constexpr const char* kProgram = "analyzer";
constexpr const char* kPacketsFile = "packets.txt";

struct Options {
    std::string path;
    bool show_flows = false;
    bool show_http = false;
    bool show_dns = false;
    bool show_summary = false;
    bool show_bench = false;
    bool show_packets = false;
    bool json = false;
    std::string out_dir;
    net::Decoder::Config config;
    uint64_t idle_timeout_us = FlowTable::DEFAULT_IDLE_TIMEOUT_US;
    bool help = false;
};

bool matches(const char* arg, const char* shortFlag, const char* longFlag) {
    return std::strcmp(arg, shortFlag) == 0 || std::strcmp(arg, longFlag) == 0;
}

void printUsage(std::ostream& os) {
    os <<
        "usage: " << kProgram << " <capture.pcap> [options]\n"
        "\n"
        "output selection (default: --summary --flows)\n"
        "  -f, --flows        per-flow table, sorted by bytes\n"
        "  -H, --http         HTTP requests and responses, grouped by flow\n"
        "  -d, --dns          DNS questions and answers, and resolved names\n"
        "  -s, --summary      packet, flow and byte counters\n"
        "  -b, --bench        capture read and decode timings\n"
        "  -p, --packets      every decoded packet and its layers (not in --all)\n"
        "  -a, --all          all of the above except --packets\n"
        "\n"
        "options\n"
        "  -j, --json         print --packets/--flows as JSON instead of text\n"
        "  -o, --out DIR      write each section to its own file in DIR\n"
        "  -n, --limit N      print at most N rows per section (0 = no limit)\n"
        "  -C, --no-checksum  accept packets with bad IP/TCP/UDP/ICMP checksums\n"
        "  -t, --timeout SEC  retire an active flow after SEC seconds (default: 0 = never)\n"
        "  -i, --idle SEC     retire a flow after SEC idle seconds (default: 30)\n"
        "  -h, --help         this message\n"
        "\n"
        "filtering (directional, AND-combined; non-matching packets are dropped\n"
        "before decoding and excluded from every section and the skip counter)\n"
        "      --src-ip ADDR   keep only packets from this IPv4/IPv6 address\n"
        "      --dst-ip ADDR   keep only packets to this IPv4/IPv6 address\n"
        "      --src-port N    keep only packets from this port\n"
        "      --dst-port N    keep only packets to this port\n"
        "      --proto NAME    keep only this L4 protocol (tcp|udp|icmp|icmpv6|<num>)\n";
}

bool parseFilterIp(const char* text, uint8_t out_ip[16], bool& is_ipv4) {
    uint8_t v4[4];
    if (net::ip::v4::addressFromString(text, v4)) {
        std::memset(out_ip, 0, 16);
        std::memcpy(out_ip, v4, 4);
        is_ipv4 = true;
        return true;
    }
    uint8_t v6[16];
    if (net::ip::v6::addressFromString(text, v6)) {
        std::memcpy(out_ip, v6, 16);
        is_ipv4 = false;
        return true;
    }
    return false;
}

bool parseArgs(int argc, char** argv, Options& out) {
    int ip_version = 0;
    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];

        auto nextValue = [&](const char* what) -> const char* {
            if (i + 1 >= argc) {
                std::cerr << kProgram << ": " << arg << " requires " << what << "\n";
                return nullptr;
            }
            return argv[++i];
        };

        if (matches(arg, "-h", "--help")) {
            out.help = true;
            return true;
        } else if (matches(arg, "-f", "--flows")) {
            out.show_flows = true;
        } else if (matches(arg, "-H", "--http")) {
            out.show_http = true;
        } else if (matches(arg, "-d", "--dns")) {
            out.show_dns = true;
        } else if (matches(arg, "-s", "--summary")) {
            out.show_summary = true;
        } else if (matches(arg, "-b", "--bench")) {
            out.show_bench = true;
        } else if (matches(arg, "-p", "--packets")) {
            out.show_packets = true;
        } else if (matches(arg, "-j", "--json")) {
            out.json = true;
        } else if (matches(arg, "-o", "--out")) {
            const char* s = nextValue("a directory");
            if (!s) return false;
            out.out_dir = s;
            if (out.out_dir.empty()) {
                std::cerr << kProgram << ": empty output directory\n";
                return false;
            }
        } else if (matches(arg, "-a", "--all")) {
            out.show_summary = true;
            out.show_flows = true;
            out.show_http = true;
            out.show_dns = true;
            out.show_bench = true;
        } else if (matches(arg, "-C", "--no-checksum")) {
            out.config.verify_checksum = false;
        } else if (matches(arg, "-n", "--limit")) {
            const char* s = nextValue("a count");
            if (!s) return false;
            uint64_t value = 0;
            if (!util::parseUint(s, value, SIZE_MAX)) {
                std::cerr << kProgram << ": invalid count '" << s << "'\n";
                return false;
            }
            out.config.print_limit = static_cast<size_t>(value);
        } else if (matches(arg, "-t", "--timeout")) {
            const char* s = nextValue("a number of seconds");
            if (!s) return false;
            uint64_t sec = 0;
            if (!util::parseUint(s, sec, UINT64_MAX / 1000000)) {
                std::cerr << kProgram << ": invalid timeout '" << s << "'\n";
                return false;
            }
            out.config.flow_active_timeout_us = sec * 1000000;
        } else if (matches(arg, "-i", "--idle")) {
            const char* s = nextValue("a number of seconds");
            if (!s) return false;
            uint64_t sec = 0;
            if (!util::parseUint(s, sec, UINT64_MAX / 1000000)) {
                std::cerr << kProgram << ": invalid idle timeout '" << s << "'\n";
                return false;
            }
            out.config.flow_idle_timeout_us = sec * 1000000;
        } else if (std::strcmp(arg, "--src-ip") == 0 || std::strcmp(arg, "--dst-ip") == 0) {
            const char* s = nextValue("an address");
            if (!s) return false;
            uint8_t ip[16];
            bool is_ipv4 = false;
            if (!parseFilterIp(s, ip, is_ipv4)) {
                std::cerr << kProgram << ": invalid address '" << s << "'\n";
                return false;
            }
            const int version = is_ipv4 ? 4 : 6;
            if (ip_version != 0 && ip_version != version) {
                std::cerr << kProgram << ": mixed IPv4/IPv6 address filter\n";
                return false;
            }
            ip_version = version;
            out.config.filter.isIpv4 = is_ipv4;
            std::memcpy(arg[2] == 'd' ? out.config.filter.dst_ip : out.config.filter.src_ip, ip, 16);
        } else if (std::strcmp(arg, "--src-port") == 0 || std::strcmp(arg, "--dst-port") == 0) {
            const char* s = nextValue("a port");
            if (!s) return false;
            uint64_t value = 0;
            if (!util::parseUint(s, value, 65535) || value == 0) {
                std::cerr << kProgram << ": invalid port '" << s << "'\n";
                return false;
            }
            (arg[2] == 'd' ? out.config.filter.dst_port : out.config.filter.src_port) = static_cast<uint16_t>(value);
        } else if (std::strcmp(arg, "--proto") == 0) {
            const char* s = nextValue("a protocol");
            if (!s) return false;
            uint8_t proto = 0;
            if (!net::ip::protocolFromName(s, proto) || proto == 0) {
                std::cerr << kProgram << ": invalid protocol '" << s << "'\n";
                return false;
            }
            out.config.filter.protocol = proto;
        } else if (arg[0] == '-' && arg[1] != '\0') {
            std::cerr << kProgram << ": unknown option '" << arg << "'\n";
            return false;
        } else if (out.path.empty()) {
            out.path = arg;
        } else {
            std::cerr << kProgram << ": unexpected argument '" << arg << "'\n";
            return false;
        }
    }

    if (!out.help && out.path.empty()) {
        std::cerr << kProgram << ": no capture file given\n";
        return false;
    }
    if (!out.show_flows && !out.show_http && !out.show_dns && !out.show_summary && !out.show_bench
        && !out.show_packets) {
        if (out.out_dir.empty()) {
            out.show_summary = true;
            out.show_flows = true;
        } else {
            out.show_summary = true;
            out.show_flows = true;
            out.show_http = true;
            out.show_dns = true;
            out.show_bench = true;
            out.show_packets = true;
        }
    }
    return true;
}

void printSummary(std::ostream& os, const pcap::Reader& reader) {
    const FlowTable& table = reader.flowTable();
    size_t flow_count = table.completed().size() + table.flows().size();

    size_t http_messages = 0;
    size_t dns_messages = 0;
    size_t decode_failures = 0;
    size_t http_bodies_skipped = 0;
    for (const auto& [key, flow] : table.allFlows()) {
        (void)flow;
        for (bool reverse : {false, true}) {
            const Applications* apps = reader.appDecoder().getApplications(*key, reverse);
            if (!apps) continue;
            http_messages += apps->http_messages.size();
            dns_messages += apps->dns_messages.size();
            decode_failures += apps->decode_failures;
            http_bodies_skipped += apps->http_bodies_skipped;
        }
    }

    os << "summary\n";
    os << "  packets decoded   " << reader.decoded() << '\n';
    os << "  packets skipped   " << reader.skipped();
    if (reader.skipped()) os << "  (last: " << reader.lastSkipErr() << ')';
    os << '\n';
    os << "  bytes             " << table.total_bytes() << '\n';
    os << "  flows             " << flow_count
       << "  (" << table.flows().size() << " active, "
       << table.completed().size() << " retired)\n";
    if (dns_messages) {    
        os << "  dns messages      " << dns_messages << '\n';
    }
    if (http_messages) {    
        os << "  http messages     " << http_messages << '\n';
    }
    if (decode_failures) {
        os << "  decode failures   " << decode_failures << '\n';
    }
    if (http_bodies_skipped) {
        os << "  http bodies skipped " << http_bodies_skipped
           << "  (>" << (MAX_HTTP_MESSAGE_BYTES / (1024 * 1024)) << "MB, not decode failures)\n";
    }
    os << "  total time        " << Benchmark::formatDuration(reader.benchmark().elapsedNs(Benchmark::Phase::Total)) << '\n';
    os << '\n';
}

}

int cli(int argc, char** argv) {
    Options options;
    if (!parseArgs(argc, argv, options)) {
        std::cerr << "try '" << kProgram << " --help'\n";
        return 2;
    }
    if (options.help) {
        printUsage(std::cout);
        return 0;
    }

    const std::filesystem::path dir = options.out_dir;
    if (!options.out_dir.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        if (ec) {
            std::cerr << kProgram << ": " << dir.string() << ": " << ec.message() << '\n';
            return 2;
        }
    }

    try {
        pcap::Reader reader(options.path, options.config, options.show_bench);

        std::vector<std::string> written;
        bool write_failed = false;

        std::ofstream packets_file;
        std::ostream* out = nullptr;
        if (options.show_packets) {
            if (options.out_dir.empty()) {
                out = &std::cout;
            } else {
                packets_file.open(dir / kPacketsFile);
                if (!packets_file) {
                    std::cerr << kProgram << ": cannot write " << (dir / kPacketsFile).string() << '\n';
                    return 2;
                }
                out = &packets_file;
            }
        }

        reader.setJson(options.json);

        size_t packets_written = 0;
        if (out) {
            if (options.json) *out << "[\n";
            reader.readAllPackets([&](const pcap::Capture& capture) {
                if (options.config.print_limit && packets_written >= options.config.print_limit) return;
                if (options.json && packets_written > 0) *out << ",\n";
                reader.print(*out, capture);
                ++packets_written;
                if (!options.json && packets_written == options.config.print_limit) *out << "  ... limit reached\n";
            });
            if (options.json) *out << "]\n";
            if (!options.out_dir.empty()) {
                packets_file.close();
                if (!packets_file) {
                    std::cerr << kProgram << ": failed writing " << (dir / kPacketsFile).string() << '\n';
                    write_failed = true;
                } else {
                    written.push_back(kPacketsFile);
                }
            }
        } else {
            reader.readAllPackets();
        }

        auto emit = [&](const char* name, auto&& render) {
            if (options.out_dir.empty()) {
                render(std::cout);
                return;
            }
            std::ofstream file(dir / name);
            if (file) render(file);
            file.close();
            if (!file) {
                std::cerr << kProgram << ": cannot write " << (dir / name).string() << '\n';
                write_failed = true;
                return;
            }
            written.push_back(name);
        };

        if (options.show_summary) emit("summary.txt", [&](std::ostream& os) { printSummary(os, reader); });
        if (options.show_flows) {
            emit("flows.txt", [&](std::ostream& os) {
                if (options.json) os << "{\n" << util::indent(reader.statsEngine().toJson(), "  ") << "\n}\n";
                else os << reader.statsEngine() << '\n';
            });
        }
        if (options.show_http) emit("http.txt", [&](std::ostream& os) { reader.statsEngine().printHttp(os); });
        if (options.show_dns) emit("dns.txt", [&](std::ostream& os) { reader.statsEngine().printDns(os); });
        if (options.show_bench) emit("bench.txt", [&](std::ostream& os) { reader.statsEngine().printBenchmark(os); });

        if (!options.out_dir.empty() && !written.empty()) {
            std::cout << kProgram << ": wrote " << written.size()
                      << (written.size() == 1 ? " file to " : " files to ") << dir.string() << '\n';
            for (const std::string& name : written) {
                std::cout << "  " << name;
                if (name == kPacketsFile) std::cout << "  (" << packets_written << " packets)";
                std::cout << '\n';
            }
        }
        if (write_failed) return 1;
    } catch (const std::exception& e) {
        std::cerr << kProgram << ": " << options.path << ": " << e.what() << '\n';
        return 1;
    }

    return 0;
}