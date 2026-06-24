#include <net/protocols/ipv6.h>
#include <net/core/checksum.h>

#include <cstring>
#include <iomanip>

namespace net::ip::v6 {

ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian) {
    if (span.size() < HEADER_LEN) return ParseError::UnexpectedEof;
    std::memcpy(&header, span.data(), HEADER_LEN);

    header.version_tc_fl = toHost32(header.version_tc_fl, endian);
    header.payload_length = toHost16(header.payload_length, endian);

    uint32_t version = header.version_tc_fl >> 28;
    if (version != 6) {
        return ParseError::InvalidFieldValue;
    }
    span = span.subspan(HEADER_LEN);
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

std::ostream& operator<<(std::ostream& os, const Header& h) {
    os << "IPv6Header {\n"
        << "  version: " << (h.version_tc_fl >> 28) << '\n'
        << "  traffic_class: " << ((h.version_tc_fl >> 20) & 0xFF) << '\n'
        << "  flow_label: 0x" << std::hex << std::setfill('0') << std::setw(5) << (h.version_tc_fl & 0xFFFFF) << std::dec << '\n'
        << "  payload_length: " << h.payload_length << '\n'
        << "  next_header: " << static_cast<int>(h.next_header) << '\n'
        << "  hop_limit: " << static_cast<int>(h.hop_limit) << '\n'
        << "  src_ip: ";
    for (int i = 0; i < 16; i+= 2) {
        if (i) os << ':';
        os << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(h.src_ip[i]) << std::setw(2) << static_cast<int>(h.src_ip[i+1]);
    }
    os << '\n'
        << "  dst_ip: ";
    for (int i = 0; i < 16; i += 2) {
        if (i) os << ':';
        os << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(h.dst_ip[i]) << std::setw(2) << static_cast<int>(h.dst_ip[i+1]);
    }
    os << '\n'
        << "}";
    return os;
}

}