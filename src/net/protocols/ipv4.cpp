#include <net/protocols/ipv4.h>
#include <net/core/checksum.h>

#include <cstring>

namespace net::ip::v4 {
    ParseError parse(std::span<uint8_t>& span, Header& header, Endian endian) {
        if (span.size() < MIN_HEADER_LEN) return ParseError::UnexpectedEof;
        std::memcpy(&header, span.data(), MIN_HEADER_LEN);

        uint8_t version = header.version_ihl >> 4;
        uint8_t ihl = header.version_ihl & 0x0F;
        size_t header_len = 4 * ihl;
        if (header_len < MIN_HEADER_LEN || header_len > MAX_HEADER_LEN) {
            return ParseError::MalformedHeader;
        }
        if (span.size() < header_len) {
            return ParseError::UnexpectedEof;
        }
        if (version != 4) {
            return ParseError::InvalidFieldValue;
        }
        if (!verifyChecksum(span.data(), header_len)) {
            return ParseError::ChecksumMismatch;
        }

        header.total_length = toHost16(header.total_length, endian);
        header.identification = toHost16(header.identification, endian);
        header.flags_fragment = toHost16(header.flags_fragment, endian);
        header.checksum = toHost16(header.checksum, endian);
        header.src_ip = toHost32(header.src_ip, endian);
        header.dst_ip = toHost32(header.dst_ip, endian);

        span = span.subspan(header_len);
        return ParseError::None;
    }
    uint64_t computePseudoHeaderSum(const Header& header) {
        uint64_t sum = 0;
        
        sum += header.src_ip >> 16;
        sum += header.src_ip & 0xFFFF;
        sum += header.dst_ip >> 16;
        sum += header.dst_ip & 0xFFFF;
        sum += header.protocol;
        sum += header.total_length - 4 * (header.version_ihl & 0x0F);
        return sum;
    }
    
    std::ostream& operator<<(std::ostream& os, const Header& h) {
        os << "IPv4Header {\n";
        os << "  version: " << (h.version_ihl >> 4) << "\n";
        os << "  ihl: " << (h.version_ihl & 0x0F) << "\n";
        os << "  tos: " << (int)h.tos << "\n";
        os << "  total_length: " << h.total_length << "\n";
        os << "  identification: " << h.identification << "\n";
        os << "  flags_fragment: " << h.flags_fragment << "\n";
        os << "  ttl: " << (int)h.ttl << "\n";
        os << "  protocol: " << (int)h.protocol << "\n";
        os << "  checksum: " << (int)h.checksum<< "\n";
        os << "  src_ip: " 
           << ((h.src_ip >> 24) & 0xFF) << "."
           << ((h.src_ip >> 16) & 0xFF) << "."
           << ((h.src_ip >> 8) & 0xFF) << "."
           << (h.src_ip & 0xFF) << "\n";
        os << "  dst_ip: "
           << ((h.dst_ip >> 24) & 0xFF) << "."
           << ((h.dst_ip >> 16) & 0xFF) << "."
           << ((h.dst_ip >> 8) & 0xFF) << "."
           << (h.dst_ip & 0xFF) << "\n";
        os << "}";
        return os;
    }
}