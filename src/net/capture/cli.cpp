#include <net/capture/cli.h>
#include <net/util/text.h>

#include <algorithm>
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
    bool verify_checksum = true;
    size_t limit = 0;
    uint64_t flow_timeout_us = 0;
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
        "  -p, --packets      every decoded packet and its layers (not part of --all;\n"
        "                     with --bench, the time spent writing it is counted in\n"
        "                     the total phase)\n"
        "  -a, --all          all of the above except --packets\n"
        "\n"
        "options\n"
        "  -j, --json         print --packets as a JSON array and --flows as a JSON\n"
        "                     object instead of text (has no effect on --http/--dns/\n"
        "                     --summary/--bench, which have no JSON form)\n"
        "  -o, --out DIR  write each selected section to its own file in DIR\n"
        "                     (summary.txt, flows.txt, http.txt, dns.txt, bench.txt,\n"
        "                      packets.txt) instead of stdout; DIR is created if it\n"
        "                     does not exist, and with no section selected every\n"
        "                     section is written\n"
        "  -n, --limit N      print at most N rows per section (0 = no limit)\n"
        "  -C, --no-checksum  accept packets with bad IP/TCP/UDP/ICMP checksums\n"
        "                     (captures taken on a sending host often carry\n"
        "                      invalid checksums due to NIC offload)\n"
        "  -t, --timeout SEC  retire a flow after SEC seconds of activity, even if\n"
        "                     it never goes idle, and start a new one under the same\n"
        "                     key (default: 0 = no timeout, a flow only retires by\n"
        "                     going idle for 30s)\n"
        "  -i, --idle SEC     retire a flow after SEC seconds without a packet, so a\n"
        "                     later packet reusing the same 5-tuple starts a new flow\n"
        "                     instead of joining the old one (default: 30)\n"
        "  -h, --help         this message\n";
}

bool parseArgs(int argc, char** argv, Options& out) {
    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];

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
            if (i + 1 >= argc) {
                std::cerr << kProgram << ": " << arg << " requires a directory\n";
                return false;
            }
            out.out_dir = argv[++i];
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
            out.verify_checksum = false;
        } else if (matches(arg, "-n", "--limit")) {
            if (i + 1 >= argc) {
                std::cerr << kProgram << ": " << arg << " requires a count\n";
                return false;
            }
            char* end = nullptr;
            long value = std::strtol(argv[++i], &end, 10);
            if (!end || *end != '\0' || value < 0) {
                std::cerr << kProgram << ": invalid count '" << argv[i] << "'\n";
                return false;
            }
            out.limit = static_cast<size_t>(value);
        } else if (matches(arg, "-t", "--timeout")) {
            if (i + 1 >= argc) {
                std::cerr << kProgram << ": " << arg << " requires a number of seconds\n";
                return false;
            }
            char* end = nullptr;
            long value = std::strtol(argv[++i], &end, 10);
            if (!end || *end != '\0' || value < 0) {
                std::cerr << kProgram << ": invalid timeout '" << argv[i] << "'\n";
                return false;
            }
            out.flow_timeout_us = static_cast<uint64_t>(value) * 1'000'000;
        } else if (matches(arg, "-i", "--idle")) {
            if (i + 1 >= argc) {
                std::cerr << kProgram << ": " << arg << " requires a number of seconds\n";
                return false;
            }
            char* end = nullptr;
            long value = std::strtol(argv[++i], &end, 10);
            if (!end || *end != '\0' || value < 0) {
                std::cerr << kProgram << ": invalid idle timeout '" << argv[i] << "'\n";
                return false;
            }
            out.idle_timeout_us = static_cast<uint64_t>(value) * 1'000'000;
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
        pcap::Reader reader(options.path, options.limit, options.show_bench, options.verify_checksum, options.flow_timeout_us, options.idle_timeout_us);

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
                if (options.limit && packets_written >= options.limit) return;
                if (options.json && packets_written > 0) *out << ",\n";
                reader.print(*out, capture);
                ++packets_written;
                if (!options.json && packets_written == options.limit) *out << "  ... limit reached\n";
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