#include <net/protocols/arp.h>
#include <net/protocols/ethernet.h>
#include <net/protocols/ipv4.h>

#include <cstring>
#include <iomanip>
#include <sstream>

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

std::string Header::toString() const noexcept {
    std::ostringstream oss;
    auto printHex = [&](const uint8_t* p, uint8_t len) {
        for (uint8_t i = 0; i < len; ++i) {
            if (i) oss << '-';
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(p[i]);
        }
        oss << std::dec;
    };
    auto printHw = [&](const uint8_t* p) {
        if (htype == HTYPE_ETHERNET) ethernet::printMac(oss, p);
        else printHex(p, hlen);
    };
    auto printProto = [&](const uint8_t* p) {
        if (ptype == ethernet::ETHERTYPE_IPV4) ip::v4::printIp(oss, p);
        else printHex(p, plen);
    };

    oss << "ArpHeader {\n"
        << "  htype: " << htype;
    if (htype == HTYPE_ETHERNET) oss << " (Ethernet)";
    oss << '\n'
        << "  ptype: 0x" << std::hex << std::setfill('0') << std::setw(4) << ptype << std::dec;
    if (ptype == ethernet::ETHERTYPE_IPV4) oss << " (IPv4)";
    oss << '\n'
        << "  oper: " << oper;
    if (oper == OPER_REQUEST) oss << " (request)";
    else if (oper == OPER_REPLY) oss << " (reply)";
    oss << '\n'
        << "  sha: "; printHw(sha); oss << '\n'
        << "  spa: "; printProto(spa); oss << '\n'
        << "  tha: "; printHw(tha); oss << '\n'
        << "  tpa: "; printProto(tpa); oss << '\n'
        << "}";
    return oss.str();
}

std::string Header::toJson() const noexcept {
    std::ostringstream oss;
    auto printHex = [&](const uint8_t* p, uint8_t len) {
        for (uint8_t i = 0; i < len; ++i) {
            if (i) oss << '-';
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(p[i]);
        }
        oss << std::dec;
    };
    auto printHw = [&](const uint8_t* p) {
        if (htype == HTYPE_ETHERNET) ethernet::printMac(oss, p);
        else printHex(p, hlen);
    };
    auto printProto = [&](const uint8_t* p) {
        if (ptype == ethernet::ETHERTYPE_IPV4) ip::v4::printIp(oss, p);
        else printHex(p, plen);
    };

    oss << "\"arp\": {\n"
        << "  \"htype\": " << htype << ",\n"
        << "  \"ptype\": \"0x" << std::hex << std::setfill('0') << std::setw(4) << ptype << std::dec << "\",\n"
        << "  \"oper\": " << oper << ",\n"
        << "  \"sha\": \""; printHw(sha); oss << "\",\n"
        << "  \"spa\": \""; printProto(spa); oss << "\",\n"
        << "  \"tha\": \""; printHw(tha); oss << "\",\n"
        << "  \"tpa\": \""; printProto(tpa); oss << "\"\n"
        << "}";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    return os << h.toString();
}

}