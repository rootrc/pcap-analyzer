#include <net/protocols/ethernet.h>

#include <cstring>
#include <iomanip>
#include <sstream>

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

std::string Header::toString() const noexcept {
    std::ostringstream oss;
    oss << "EthernetHeader {\n"
        << "  dst_mac: ";
    printMac(oss, dst_mac);
    oss << '\n'
        << "  src_mac: ";
    printMac(oss, src_mac);
    oss << '\n'
        << "  ethertype: 0x" << std::hex << std::setfill('0') << std::setw(4) << ethertype << " ("  << ethertypeName(ethertype) << std::dec << ")\n"
        << "}";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    return os << h.toString();
}

}