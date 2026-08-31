#include <net/capture/cli.h>

#include <algorithm>
#include <iostream>
#include <vector>
#include <map>

using namespace net;

namespace {

constexpr const char* kProgram = "analyzer";

struct Options {
    std::string path;
    bool show_flows = false;
    bool show_http = false;
    bool show_dns = false;
    bool show_summary = false;
    size_t limit = 0;
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
        "  -a, --all          all of the above\n"
        "\n"
        "options\n"
        "  -n, --limit N      print at most N rows per section (0 = no limit)\n"
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
        } else if (matches(arg, "-a", "--all")) {
            out.show_summary = true;
            out.show_flows = true;
            out.show_http = true;
            out.show_dns = true;
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
    if (!out.show_flows && !out.show_http && !out.show_dns && !out.show_summary) {
        out.show_summary = true;
        out.show_flows = true;
    }
    return true;
}

void printSummary(std::ostream& os, const pcap::Reader& reader) {
    const FlowTable& table = reader.flowTable();
    size_t flow_count = table.completed().size() + table.flows().size();

    size_t http_messages = 0;
    size_t dns_messages = 0;
    size_t decode_failures = 0;
    for (const auto& [key, flow] : table.allFlows()) {
        (void)flow;
        for (bool reverse : {false, true}) {
            const Applications* apps = reader.appDecoder().getApplications(*key, reverse);
            if (!apps) continue;
            http_messages += apps->http_messages.size();
            dns_messages += apps->dns_messages.size();
            decode_failures += apps->decode_failures;
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

    try {
        pcap::Reader reader(options.path, options.limit);

        reader.readAllPackets();

        if (options.show_summary) printSummary(std::cout, reader);
        if (options.show_flows) std::cout << reader.statsEngine() << '\n';
        if (options.show_http) reader.statsEngine().printHttp(std::cout);
        if (options.show_dns) reader.statsEngine().printDns(std::cout);
    } catch (const std::exception& e) {
        std::cerr << kProgram << ": " << options.path << ": " << e.what() << '\n';
        return 1;
    }

    return 0;
}