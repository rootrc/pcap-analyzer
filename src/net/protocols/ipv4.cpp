#include <net/protocols/ipv4.h>
#include <net/protocols/ip.h>
#include <net/util/checksum.h>

#include <cstring>
#include <iomanip>
#include <sstream>

namespace net::ip::v4 {

ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian) {
    if (span.size() < MIN_HEADER_LEN) return ParseError::UnexpectedEof;
    std::memcpy(&header, span.data(), MIN_HEADER_LEN);

    if (header.header_length() < MIN_HEADER_LEN || header.header_length() > MAX_HEADER_LEN) {
        return ParseError::MalformedHeader;
    }
    if (span.size() < header.header_length()) {
        return ParseError::UnexpectedEof;
    }
    if (header.version() != SUPPORTED_VERSION) {
        return ParseError::InvalidFieldValue;
    }
    if (!verifyChecksum(span.data(), header.header_length())) {
        return ParseError::ChecksumMismatch;
    }

    header.total_length = toHost16(header.total_length, endian);
    header.identification = toHost16(header.identification, endian);
    header.flags_fragment = toHost16(header.flags_fragment, endian);
    header.checksum = toHost16(header.checksum, endian);
    header.src_ip = toHost32(header.src_ip, endian);
    header.dst_ip = toHost32(header.dst_ip, endian);
    
    if (header.total_length > span.size()) return ParseError::UnexpectedEof;
    span = span.subspan(header.header_length(), header.total_length - header.header_length());
    return ParseError::None;
}

uint64_t computePseudoHeaderSum(const Header& header) {
    uint64_t sum = 0;
    
    sum += header.src_ip >> 16;
    sum += header.src_ip & 0xFFFF;
    sum += header.dst_ip >> 16;
    sum += header.dst_ip & 0xFFFF;
    sum += header.protocol;
    sum += header.total_length - sizeof(uint32_t) * header.ihl();
    return sum;
}

std::ostream& printIp(std::ostream& os, const uint32_t ip) {
    return os << ((ip >> 24) & 0xFF) << '.'
              << ((ip >> 16) & 0xFF) << '.'
              << ((ip >> 8) & 0xFF) << '.'
              << (ip & 0xFF);
}

std::ostream& printIp(std::ostream& os, const uint8_t ip[4]) {
    return os << static_cast<int>(ip[0]) << '.'
              << static_cast<int>(ip[1]) << '.'
              << static_cast<int>(ip[2]) << '.'
              << static_cast<int>(ip[3]);
}

std::string Header::toString() const noexcept {
    std::ostringstream oss;
    oss << "IPv4Header {\n"
        << "  version: " << static_cast<int>(version()) << '\n'
        << "  ihl: " << static_cast<int>(ihl()) << '\n'
        << "  tos: 0x" << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(tos) << std::dec << '\n'
        << "  total_length: " << total_length << '\n'
        << "  identification: " << identification << '\n'
        << "  flags: "
        << ((dontFragment()) ? "DF" : "")
        << ((moreFragments()) ? "MF" : "")
        << ((!dontFragment() && !moreFragments()) ? "none" : "")
        << " (0b" << ((flags() >> 2) & 1)
        << ((flags() >> 1) & 1)
        << (flags() & 1) << ")\n"
        << "  fragment: " << std::hex << std::setfill('0') << std::setw(4) <<  static_cast<int>(fragment()) << std::dec << '\n'
        << "  ttl: " << static_cast<int>(ttl) << '\n'
        << "  protocol: " << static_cast<int>(protocol) << " (" << ip::protocolName(protocol) << ")\n"
        << "  checksum: 0x" << std::hex << checksum << std::dec << '\n'
        << "  src_ip: " ; printIp(oss, src_ip); oss << '\n'
        << "  dst_ip: "; printIp(oss, dst_ip); oss << '\n'
        << "}";
    return oss.str();
}

std::string Header::toJson() const noexcept {
    std::ostringstream oss;
    oss << "\"ipv4\": {\n"
        << "  \"version\": " << static_cast<int>(version()) << ",\n"
        << "  \"ihl\": " << static_cast<int>(ihl()) << ",\n"
        << "  \"tos\": \"0x" << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(tos) << std::dec << "\",\n"
        << "  \"total_length\": " << total_length << ",\n"
        << "  \"identification\": " << identification << ",\n"
        << "  \"flags\": [";
    bool firstFlag = true;
    if (dontFragment()) { if(!firstFlag) oss << ", "; oss << "\"DF\""; firstFlag=false; }
    if (moreFragments()) { if(!firstFlag) oss << ", "; oss << "\"MF\""; firstFlag=false; }
    oss << "],\n"
        << "  \"fragment\": \"0x" << std::hex << std::setfill('0') << std::setw(4) << static_cast<int>(fragment()) << std::dec << "\",\n"
        << "  \"ttl\": " << static_cast<int>(ttl) << ",\n"
        << "  \"protocol\": " << static_cast<int>(protocol) << ",\n"
        << "  \"checksum\": \"0x" << std::hex << checksum << std::dec << "\",\n"
        << "  \"src_ip\": \""; printIp(oss, src_ip); oss << "\",\n"
        << "  \"dst_ip\": \""; printIp(oss, dst_ip); oss << "\"\n"
        << "}";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    return os << h.toString();
}

}