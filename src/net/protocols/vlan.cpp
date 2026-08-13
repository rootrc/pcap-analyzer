#include <net/protocols/vlan.h>
#include <net/protocols/ethernet.h>

#include <cstring>
#include <iomanip>
#include <sstream>

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

std::string Header::toString() const noexcept {
    std::ostringstream oss;
    oss << "VLANHeader {\n"
        << "  pcp: " << static_cast<int>(pcp()) << '\n'
        << "  dei: " << static_cast<int>(dei()) << '\n'
        << "  vid: " << vid() << '\n'
        << "  ethertype: 0x" << std::hex << std::setfill('0') << std::setw(4) << ethertype << " ("  << ethernet::ethertypeName(ethertype) << std::dec << ")\n"
        << "}";
    return oss.str();
}

std::string Header::toJson() const noexcept {
    std::ostringstream oss;
    oss << "\"vlan\": {\n"
        << "  \"pcp\": " << static_cast<int>(pcp()) << ",\n"
        << "  \"dei\": " << static_cast<int>(dei()) << ",\n"
        << "  \"vid\": " << vid() << ",\n"
        << "  \"ethertype\": \"0x" << std::hex << std::setfill('0') << std::setw(4) << ethertype << std::dec << "\"\n"
        << "}";
    return oss.str();
}


std::ostream& operator<<(std::ostream& os, const Header& h) {
    return os << h.toString();
}

}