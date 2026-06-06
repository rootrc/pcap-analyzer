#include <net/protocols/udp.h>
#include <net/core/checksum.h>

#include <cstring>

namespace net::udp {
    ParseError parse(BufferView& buf, Header& header, uint64_t pseudoHeaderSum, Endian endian);

    ParseError parse(BufferView& buf, Header& header, const ip::v4::Header& ip_header, Endian endian) {
        return parse(buf, header, ip::v4::computePseudoHeaderSum(ip_header), endian);
    }

    ParseError parse(BufferView& buf, Header& header, const ip::v6::Header& ip_header, Endian endian) {
        return parse(buf, header, ip::v6::computePseudoHeaderSum(ip_header), endian);
    }

    ParseError parse(BufferView& buf, Header& header, uint64_t pseudoHeaderSum, Endian endian) {
        if (buf.length() < HEADER_LEN) return ParseError::UnexpectedEof;
        std::memcpy(&header, buf.current(), HEADER_LEN);
        if (toHost16(header.length, endian) < HEADER_LEN || buf.length() < toHost16(header.length, endian)) {
            return ParseError::MalformedHeader;
        }
        if (header.checksum != 0 && !verifyChecksum(buf.current(), toHost16(header.length, endian), pseudoHeaderSum)) {
            return ParseError::ChecksumMismatch;
        }
        header.src_port = toHost16(header.src_port, endian);
        header.dst_port = toHost16(header.dst_port, endian);
        header.length = toHost16(header.length, endian);
        header.checksum = toHost16(header.checksum, endian);

        buf.advance(HEADER_LEN);
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