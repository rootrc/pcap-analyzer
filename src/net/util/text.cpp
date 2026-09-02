#include <net/util/text.h>

#include <cctype>
#include <iomanip>

namespace util {

bool isEquals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

std::string indent(std::string_view str, std::string_view prefix) {
    if (str.empty()) return {};

    std::string out;
    out.reserve(str.size() + prefix.size());

    std::size_t pos = 0;
    while (pos < str.size()) {
        out.append(prefix);
        const std::size_t new_line = str.find('\n', pos);
        if (new_line == std::string_view::npos) {
            out.append(str.data() + pos, str.size() - pos);
            break;
        }
        out.append(str.data() + pos, new_line - pos);
        out.push_back('\n');

        pos = new_line + 1;
    }

    return out;
}

void printDuration(std::ostream& os, uint64_t ns) {
    if (ns >= 1'000'000'000ULL) {
        os << std::fixed << std::setprecision(3) << (static_cast<double>(ns) / 1e9) << 's';
    } else if (ns >= 1'000'000ULL) {
        os << std::fixed << std::setprecision(2) << (static_cast<double>(ns) / 1e6) << "ms";
    } else if (ns >= 1'000ULL) {
        os << std::fixed << std::setprecision(2) << (static_cast<double>(ns) / 1e3) << "us";
    } else {
        os << ns << "ns";
    }
}

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