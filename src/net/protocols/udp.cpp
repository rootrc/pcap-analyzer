#include <net/protocols/udp.h>
#include <net/core/checksum.h>

#include <cstring>

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
        
    std::ostream& operator<<(std::ostream& os, const Header& h) {
        os << "UDPHeader {\n";
        os << "  src_port: " << h.src_port << "\n";
        os << "  dst_port: " << h.dst_port << "\n";
        os << "  length: " << h.length << "\n";
        os << "  checksum: " << h.checksum << "\n";
        os << "}";
        return os;
    }
}