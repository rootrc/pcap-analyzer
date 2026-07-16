#include <net/protocols/ethernet.h>
#include <net/protocols/ipv4.h>
#include <net/protocols/arp.h>

#include <cstring>
#include <iomanip>

namespace net::arp {

ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian) {
    if (span.size() < MIN_HEADER_LEN) return ParseError::UnexpectedEof;
    std::memcpy(&header, span.data(), MIN_HEADER_LEN);

    header.htype = toHost16(header.htype, endian);
    header.ptype = toHost16(header.ptype, endian);
    header.oper = toHost16(header.oper,  endian);

    if (header.hlen == 0 || header.plen == 0) {
        return ParseError::InvalidFieldValue;
    }
    if (header.oper != OPER_REQUEST && header.oper != OPER_REPLY) {
        return ParseError::InvalidFieldValue;
    }

    size_t header_len = MIN_HEADER_LEN + 2 * static_cast<size_t>(header.hlen) + 2 * static_cast<size_t>(header.plen);
    if (span.size() < header_len) return ParseError::UnexpectedEof;

    header.sha = span.data() + MIN_HEADER_LEN;
    header.spa = span.data() + MIN_HEADER_LEN + static_cast<size_t>(header.hlen);
    header.tha = span.data() + MIN_HEADER_LEN + static_cast<size_t>(header.hlen + header.plen);
    header.tpa = span.data() + MIN_HEADER_LEN + static_cast<size_t>(2 * header.hlen + header.plen);

    span = span.subspan(header_len);
    return ParseError::None;
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    auto printHex = [&](const uint8_t* p, uint8_t len) {
        for (uint8_t i = 0; i < len; ++i) {
            if (i) os << '-';
            os << std::hex << std::setfill('0') << std::setw(2) << (int)p[i];
        }
        os << std::dec;
    };
    auto printHw = [&](const uint8_t* p) {
        if (h.htype == HTYPE_ETHERNET) ethernet::printMac(os, p);
        else printHex(p, h.hlen);
    };
    auto printProto = [&](const uint8_t* p) {
        if (h.ptype == ethernet::ETHERTYPE_IPV4) ip::v4::printIp(os, p);
        else printHex(p, h.plen);
    };

    os << "ArpHeader {\n"
       << "  htype: " << h.htype;
    if (h.htype == HTYPE_ETHERNET) os << " (Ethernet)";
    os << '\n'
       << "  ptype: 0x" << std::hex << std::setfill('0') << std::setw(4) << h.ptype << std::dec;
    if (h.ptype == ethernet::ETHERTYPE_IPV4) os << " (IPv4)";
    os << '\n'
       << "  oper: " << h.oper;
    if (h.oper == OPER_REQUEST) os << " (request)";
    else if (h.oper == OPER_REPLY) os << " (reply)";
    os << '\n'
       << "  sha: "; printHw(h.sha); os << '\n'
       << "  spa: "; printProto(h.spa); os << '\n'
       << "  tha: "; printHw(h.tha); os << '\n'
       << "  tpa: "; printProto(h.tpa); os << '\n'
       << "}";
    return os;
}

}