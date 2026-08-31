#include <net/protocols/ipv6.h>
#include <net/protocols/ip.h>
#include <net/util/checksum.h>

#include <cstring>
#include <iomanip>
#include <sstream>

namespace net::ip::v6 {

ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian) {
    if (span.size() < HEADER_LEN) return ParseError::UnexpectedEof;
    std::memcpy(&header, span.data(), HEADER_LEN);

    header.version_tc_fl = toHost32(header.version_tc_fl, endian);
    header.payload_length = toHost16(header.payload_length, endian);

    if (header.version() != SUPPORTED_VERSION) {
        return ParseError::InvalidFieldValue;
    }
    span = span.subspan(HEADER_LEN);
    if (header.payload_length > span.size()) return ParseError::UnexpectedEof;
    span = span.first(header.payload_length);
    return ParseError::None;
}

uint64_t computePseudoHeaderSum(const Header& header) {
    uint64_t sum = 0;

    for (int i = 0; i < 16; i += 2) {
        sum += (header.src_ip[i] << 8) | header.src_ip[i + 1];
    }

    for (int i = 0; i < 16; i += 2) {
        sum += (header.dst_ip[i] << 8) | header.dst_ip[i + 1];
    }

    sum += header.payload_length;
    sum += header.next_header;
    return sum;
}

std::ostream& printIp(std::ostream& os, const uint8_t ip[16]) {
    int bestStart = -1;
    int bestLen = 0;
    for (int i = 0; i < 16; i += 2) {
        if (ip[i] << 8 != 0 || ip[i + 1] != 0) continue;

        int start = i;
        while (i < 16 && ip[i + 2] << 8 == 0 && ip[i + 3] == 0) {
            i += 2;
        }

        int len = i - start;
        if (len > bestLen && len > 0) {
            bestStart = start;
            bestLen = len;
        }
    }
    if (bestLen < 2) bestStart = -1;

    for (int i = 0; i < 16; i += 2) {
        if (i == bestStart) {
            os << ":";
            i += bestLen;
            continue;
        }
        if (i) os << ':';
        os << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(ip[i]) << std::setw(2) << static_cast<int>(ip[i+1]);
    }
    return os;
}

std::string Header::toString() const noexcept {
    std::ostringstream oss;
    oss << "IPv6Header {\n"
        << "  version: " << static_cast<int>(version()) << '\n'
        << "  traffic_class: " << static_cast<int>(tc()) << '\n'
        << "  flow_label: 0x" << std::hex << std::setfill('0') << std::setw(5) << fl() << std::dec << '\n'
        << "  payload_length: " << payload_length << '\n'
        << "  next_header: " << static_cast<int>(next_header) << " (" << ip::protocolName(next_header) << ")\n"
        << "  hop_limit: " << static_cast<int>(hop_limit) << '\n'
        << "  src_ip: "; printIp(oss, src_ip); oss << '\n'
        << "  dst_ip: "; printIp(oss, dst_ip); oss << '\n'
        << "}";
    return oss.str();
}

std::string Header::toJson() const noexcept {
    std::ostringstream oss;
    oss << "\"ipv6\": {\n"
        << "  \"version\": " << static_cast<int>(version()) << ",\n"
        << "  \"traffic_class\": " << static_cast<int>(tc()) << ",\n"
        << "  \"flow_label\": \"0x" << std::hex << std::setfill('0') << std::setw(5) << fl() << std::dec << "\",\n"
        << "  \"payload_length\": " << payload_length << ",\n"
        << "  \"next_header\": " << static_cast<int>(next_header) << ",\n"
        << "  \"hop_limit\": " << static_cast<int>(hop_limit) << ",\n"
        << "  \"src_ip\": \""; printIp(oss, src_ip); oss << "\",\n"
        << "  \"dst_ip\": \""; printIp(oss, dst_ip); oss << "\"\n"
        << "}";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    return os << h.toString();
}

}