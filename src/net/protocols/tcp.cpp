#include <net/protocols/tcp.h>
#include <net/util/checksum.h>

#include <cstring>
#include <iomanip>
#include <sstream>

namespace net::tcp {

ParseError parse(std::span<const uint8_t>& span, Header& header, size_t length, uint64_t pseudoHeaderSum, Endian endian);

ParseError parse(std::span<const uint8_t>& span, Header& header, const ip::v4::Header& ip_header, Endian endian) {
    size_t length = ip_header.total_length - ip_header.header_length();
    return parse(span, header, length, ip::v4::computePseudoHeaderSum(ip_header), endian);
}

ParseError parse(std::span<const uint8_t>& span, Header& header, const ip::v6::Header& ip_header, Endian endian) {
    return parse(span, header, ip_header.payload_length, ip::v6::computePseudoHeaderSum(ip_header), endian);
}

ParseError parse(std::span<const uint8_t>& span, Header& header, size_t length, uint64_t pseudoHeaderSum, Endian endian) {
    if (span.size() < MIN_HEADER_LEN) return ParseError::UnexpectedEof;
    std::memcpy(&header, span.data(), MIN_HEADER_LEN);

    // uint8_t reserved = (header.data_offset_reserved >> 1) & 0x07;

    if (header.header_length() < MIN_HEADER_LEN || header.header_length() > MAX_HEADER_LEN || length < header.header_length() || span.size() < length) {
        return ParseError::MalformedHeader;
    }
    if (span.size() < header.header_length()) {
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
    span = span.subspan(header.header_length());
    return ParseError::None;
}

std::string Header::toString() const noexcept {
    std::ostringstream oss;
    oss << "TCPHeader {\n"
        << "  src_port: " << src_port << '\n'
        << "  dst_port: " << dst_port << '\n'
        << "  seq_number: " << seq_number << '\n'
        << "  ack_number: " << ack_number << '\n'
        << "  data_offset: 0x" << std::hex << static_cast<int>(data_offset()) << std::dec << '\n'
        << "  flags: "
        << (cwr() ? "CWR " : "")
        << (ece() ? "ECE " : "")
        << (urg() ? "URG " : "")
        << (ack() ? "ACK " : "")
        << (psh() ? "PSH " : "")
        << (rst() ? "RST " : "")
        << (syn() ? "SYN " : "")
        << (fin() ? "FIN " : "")
        << (flags == 0 ? "none " : "")
        << "(0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(flags) << std::dec << ")\n"
        << "  window_size: " << window_size << '\n'
        << "  checksum: 0x" << std::hex << std::setfill('0') << std::setw(4) << checksum << std::dec << '\n'
        << "  urgent_pointer: " << urgent_pointer << '\n'
        << "}";
    return oss.str();
}

std::string Header::toJson() const noexcept {
    std::ostringstream oss;
    oss << "\"tcp\": {\n"
        << "  \"src_port\": " << src_port << ",\n"
        << "  \"dst_port\": " << dst_port << ",\n"
        << "  \"seq_number\": " << seq_number << ",\n"
        << "  \"ack_number\": " << ack_number << ",\n"
        << "  \"data_offset\": " << static_cast<int>(data_offset()) << ",\n"
        << "  \"flags\": \"0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(flags) << std::dec << "\",\n"
        << "  \"window_size\": " << window_size << ",\n"
        << "  \"checksum\": \"0x" << std::hex << std::setfill('0') << std::setw(4) << checksum << std::dec << "\",\n"
        << "  \"urgent_pointer\": " << urgent_pointer << "\n"
        << "}";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    return os << h.toString();
}

}