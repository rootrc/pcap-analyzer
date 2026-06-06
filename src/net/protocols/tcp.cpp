#include <net/protocols/tcp.h>
#include <net/core/checksum.h>

#include <cstring>

namespace net::tcp {
    ParseError parse(BufferView& buf, Header& header, size_t length, uint64_t pseudoHeaderSum, Endian endian);

    ParseError parse(BufferView& buf, Header& header, const ip::v4::Header& ip_header, Endian endian) {
        size_t ip_header_len = 4 * (ip_header.version_ihl & 0x0F);
        size_t length = ip_header.total_length - ip_header_len;
        return parse(buf, header, length, ip::v4::computePseudoHeaderSum(ip_header), endian);
    }

    ParseError parse(BufferView& buf, Header& header, const ip::v6::Header& ip_header, Endian endian) {
        return parse(buf, header, ip_header.payload_length, ip::v6::computePseudoHeaderSum(ip_header), endian);
    }

    ParseError parse(BufferView& buf, Header& header, size_t length, uint64_t pseudoHeaderSum, Endian endian) {
        if (buf.length() < length) return ParseError::UnexpectedEof;
        std::memcpy(&header, buf.current(), MIN_HEADER_LEN);

        uint8_t data_offset = header.data_offset_reserved >> 4;
        uint8_t reserved = (header.data_offset_reserved >> 1) & 0x07;

        size_t header_len = 4 * data_offset;

        if (header_len < MIN_HEADER_LEN || header_len > MAX_HEADER_LEN) {
            return ParseError::MalformedHeader;
        }
        if (buf.length() < header_len) {
            return ParseError::UnexpectedEof;
        }
        if (reserved != 0) {
            return ParseError::InvalidFieldValue;
        }
        if (!verifyChecksum(buf.current(), length, pseudoHeaderSum)) {
            return ParseError::ChecksumMismatch;
        }

        header.src_port = toHost16(header.src_port, endian);
        header.dst_port = toHost16(header.dst_port, endian);
        header.seq_number = toHost32(header.seq_number, endian);
        header.ack_number = toHost32(header.ack_number, endian);
        header.window_size = toHost16(header.window_size, endian);
        header.urgent_pointer = toHost16(header.urgent_pointer, endian);
        buf.advance(header_len);
        return ParseError::None;
    }

    std::ostream& operator<<(std::ostream& os, const Header& h) {
        os << "TCPHeader {\n";
        os << "  src_port: " << h.src_port << "\n";
        os << "  dst_port: " << h.dst_port << "\n";
        os << "  seq_number: " << h.seq_number << "\n";
        os << "  ack_number: " << h.ack_number << "\n";
        os << "  data_offset_reserved: 0x" << std::hex << static_cast<int>(h.data_offset_reserved) << std::dec << "\n";
        os << "  flags: 0x" << std::hex << static_cast<int>(h.flags) << std::dec << "\n";
        os << "  window_size: " << h.window_size << "\n";
        os << "  checksum: " << h.checksum << "\n";
        os << "  urgent_pointer: " << h.urgent_pointer << "\n";
        os << "}";
        return os;
    }
}