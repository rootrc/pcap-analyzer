#include <net/protocols/ethernet.h>

#include <cstring>
#include <iomanip>

namespace net::ethernet {

ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian) {
    if (span.size() < HEADER_LEN) return ParseError::UnexpectedEof;
    std::memcpy(&header, span.data(), HEADER_LEN);

    header.ethertype = toHost16(header.ethertype, endian);
    
    span = span.subspan(HEADER_LEN);
    return ParseError::None;
}

std::ostream& printMac(std::ostream& os, const uint8_t mac[6]) {
    for (int i = 0; i < 6; ++i) {
        if (i) os << ":";
        os << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(mac[i]) << std::dec;
    }   
    return os;
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    os << "EthernetHeader {\n"
        << "  dst_mac: ";
    printMac(os, h.dst_mac);
    os << '\n'
        << "  src_mac: ";
    printMac(os, h.src_mac);
    os << '\n'
        << "  ethertype: 0x" << std::hex << std::setfill('0') << std::setw(4) << h.ethertype << " ("  << ethertypeName(h.ethertype) << std::dec << ")\n"
        << "}";
    return os;
}

}