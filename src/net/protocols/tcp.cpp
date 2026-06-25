#include <net/protocols/tcp.h>
#include <net/core/checksum.h>

#include <cstring>
#include <iomanip>

namespace net::tcp {

ParseError parse(std::span<const uint8_t>& span, Header& header, size_t length, uint64_t pseudoHeaderSum, Endian endian);

ParseError parse(std::span<const uint8_t>& span, Header& header, const ip::v4::Header& ip_header, Endian endian) {
    size_t ip_header_len = 4 * (ip_header.version_ihl & 0x0F);
    size_t length = ip_header.total_length - ip_header_len;
    return parse(span, header, length, ip::v4::computePseudoHeaderSum(ip_header), endian);
}

ParseError parse(std::span<const uint8_t>& span, Header& header, const ip::v6::Header& ip_header, Endian endian) {
    return parse(span, header, ip_header.payload_length, ip::v6::computePseudoHeaderSum(ip_header), endian);
}

ParseError parse(std::span<const uint8_t>& span, Header& header, size_t length, uint64_t pseudoHeaderSum, Endian endian) {
    if (span.size() < length) return ParseError::UnexpectedEof;
    std::memcpy(&header, span.data(), MIN_HEADER_LEN);

    uint8_t data_offset = header.data_offset_reserved >> DATA_OFFSET_OFFSET;
    // uint8_t reserved = (header.data_offset_reserved >> 1) & 0x07;

    size_t header_len = 4 * data_offset;

    if (header_len < MIN_HEADER_LEN || header_len > MAX_HEADER_LEN) {
        return ParseError::MalformedHeader;
    }
    if (span.size() < header_len) {
        return ParseError::UnexpectedEof;
    }
    // if (reserved != 0) {
    //     return ParseError::InvalidFieldValue;
    // }
    if (!verifyChecksum(span.data(), length, pseudoHeaderSum)) {
        return ParseError::ChecksumMismatch;
    }

    header.src_port = toHost16(header.src_port, endian);
    header.dst_port = toHost16(header.dst_port, endian);
    header.seq_number = toHost32(header.seq_number, endian);
    header.ack_number = toHost32(header.ack_number, endian);
    header.window_size = toHost16(header.window_size, endian);
    header.urgent_pointer = toHost16(header.urgent_pointer, endian);
    span = span.subspan(header_len);
    return ParseError::None;
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    os << "TCPHeader {\n"
        << "  src_port: " << h.src_port << '\n'
        << "  dst_port: " << h.dst_port << '\n'
        << "  seq_number: " << h.seq_number << '\n'
        << "  ack_number: " << h.ack_number << '\n'
        << "  data_offset: 0x" << std::hex << static_cast<int>(h.data_offset_reserved >> DATA_OFFSET_OFFSET) << std::dec << '\n'
        << "  flags: 0x" << std::hex << static_cast<int>(h.flags) << std::dec << '\n'
        << "  window_size: " << h.window_size << '\n'
        << "  checksum: 0x" << std::hex << std::setfill('0') << std::setw(4) << h.checksum << std::dec << '\n'
        << "  urgent_pointer: " << h.urgent_pointer << '\n'
        << "}";
    return os;
}

}