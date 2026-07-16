#include <net/protocols/ipv4.h>
#include <net/protocols/ip.h>
#include <net/core/checksum.h>

#include <cstring>
#include <iomanip>

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

    span = span.subspan(header.header_length());
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

std::ostream& operator<<(std::ostream& os, const Header& h) {
    os << "IPv4Header {\n"
        << "  version: " << static_cast<int>(h.version()) << '\n'
        << "  ihl: " << static_cast<int>(h.ihl()) << '\n'
        << "  tos: 0x" << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(h.tos) << std::dec << '\n'
        << "  total_length: " << h.total_length << '\n'
        << "  identification: " << h.identification << '\n'
        << "  flags: "
        << ((h.dontFragment()) ? "DF" : "")
        << ((h.moreFragments()) ? "MF" : "")
        << ((!h.dontFragment() && !h.moreFragments()) ? "none" : "")
        << " (0b" << ((h.flags() >> 2) & 1)
        << ((h.flags() >> 1) & 1)
        << (h.flags() & 1) << ")\n"
        << "  fragment: " << h.fragment() << '\n'
        << "  ttl: " << static_cast<int>(h.ttl) << '\n'
        << "  protocol: " << static_cast<int>(h.protocol) << " (" << ip::protocolName(h.protocol) << ")\n"
        << "  checksum: 0x" << std::hex << h.checksum << std::dec << '\n'
        << "  src_ip: " ;
        printIp(os, h.src_ip);
    os << '\n'
        << "  dst_ip: ";
    printIp(os, h.dst_ip);
    os << '\n'
        << "}";
    return os;
}

}