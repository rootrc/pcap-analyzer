#include <net/protocols/udp.h>
#include <net/util/checksum.h>

#include <cstring>
#include <sstream>
#include <iomanip>

namespace net::udp {

ParseError parse(std::span<const uint8_t>& span, Header& header, uint64_t pseudoHeaderSum, Endian endian);

ParseError parse(std::span<const uint8_t>& span, Header& header, const ip::v4::Header& ip_header, Endian endian) {
    return parse(span, header, ip::v4::computePseudoHeaderSum(ip_header), endian);
}

ParseError parse(std::span<const uint8_t>& span, Header& header, const ip::v6::Header& ip_header, Endian endian) {
    return parse(span, header, ip::v6::computePseudoHeaderSum(ip_header), endian);
}

ParseError parse(std::span<const uint8_t>& span, Header& header, uint64_t pseudoHeaderSum, Endian endian) {
    if (span.size() < HEADER_LEN) return ParseError::UnexpectedEof;
    std::memcpy(&header, span.data(), HEADER_LEN);
    if (toHost16(header.length, endian) < HEADER_LEN || span.size() < toHost16(header.length, endian)) {
        return ParseError::MalformedHeader;
    }
    if (header.checksum != 0 && !verifyChecksum(span.data(), toHost16(header.length, endian), pseudoHeaderSum)) {
        return ParseError::ChecksumMismatch;
    }
    header.src_port = toHost16(header.src_port, endian);
    header.dst_port = toHost16(header.dst_port, endian);
    header.length = toHost16(header.length, endian);
    header.checksum = toHost16(header.checksum, endian);

    span = span.subspan(HEADER_LEN);
    return ParseError::None;
}

std::string Header::toString() const noexcept {
    std::ostringstream oss;
    oss << "UDPHeader {\n"
        << "  src_port: " << src_port << '\n'
        << "  dst_port: " << dst_port << '\n'
        << "  length: " << length << '\n'
        << "  checksum: 0x" << std::hex << std::setfill('0') << std::setw(4) << checksum << '\n'
        << "}";
    return oss.str();
}
    
std::ostream& operator<<(std::ostream& os, const Header& h) {
    return os << h.toString();
}

}