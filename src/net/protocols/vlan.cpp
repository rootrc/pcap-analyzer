#include <net/protocols/vlan.h>
#include <net/protocols/ethernet.h>

#include <cstring>
#include <iomanip>

namespace net::vlan {

ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian) {
    if (span.size() < HEADER_LEN) return ParseError::UnexpectedEof;
    std::memcpy(&header, span.data(), HEADER_LEN);
    header.tci = toHost16(header.tci, endian);
    header.ethertype = toHost16(header.ethertype, endian);
    if (header.vid() == VID_RESERVED) {
        return ParseError::InvalidFieldValue;
    }
    span = span.subspan(HEADER_LEN);
    return ParseError::None;
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    os << "VLANHeader {\n"
        << "  pcp: " << static_cast<int>(h.pcp()) << '\n'
        << "  dei: " << static_cast<int>(h.dei()) << '\n'
        << "  vid: " << h.vid() << '\n'
        << "  ethertype: 0x" << std::hex << std::setfill('0') << std::setw(4) << h.ethertype << " ("  << ethernet::ethertypeName(h.ethertype) << std::dec << ")\n"
        << "}";
    return os;
}

}