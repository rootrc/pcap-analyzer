#include <net/protocols/ipv6_ext.h>

#include <cstring>
#include <iomanip>
#include <sstream>

namespace net::ip::v6::ext {

ParseError parse(std::span<const uint8_t>& span, Header& header, uint8_t type, Endian endian) {
    if (span.size() < MIN_HEADER_LEN) return ParseError::UnexpectedEof;
    WireHeader wire;
    std::memcpy(&wire, span.data(), MIN_HEADER_LEN);

    size_t length = 0;
    switch (type) {
        case PROTOCOL_IPV6_FRAG: length = MIN_HEADER_LEN; break;
        case PROTOCOL_AH: length = (static_cast<size_t>(wire.hdr_ext_len) + 2) * sizeof(uint32_t); break;
        default: length = (static_cast<size_t>(wire.hdr_ext_len) + 1) * MIN_HEADER_LEN; break;
    }
    if (type == PROTOCOL_AH && length < AH_MIN_LEN) {
        return ParseError::MalformedHeader;
    }
    if (span.size() < length) return ParseError::UnexpectedEof;

    header = Header{};
    header.type = type;
    header.next_header = wire.next_header;
    header.length = static_cast<uint16_t>(length);

    switch (type) {
        case PROTOCOL_IPV6_ROUTE: {
            header.routing_type = wire.routing.routing_type;
            header.segments_left = wire.routing.segments_left;
            bool addressed = header.routing_type == ROUTING_TYPE_0 || header.routing_type == ROUTING_TYPE_2 || header.routing_type == ROUTING_TYPE_SRH;
            if (!addressed || header.segments_left == 0) break;
            if (wire.hdr_ext_len < 2 || wire.hdr_ext_len % 2 != 0) {
                return ParseError::MalformedHeader;
            }
            size_t addresses = wire.hdr_ext_len / 2;
            size_t offset = offset = ROUTING_ADDRESS_OFFSET;
            if (header.routing_type != ROUTING_TYPE_SRH) {
                offset += 16 * (addresses - 1);
            }
            std::memcpy(header.final_dst, span.data() + offset, 16);
            header.has_final_dst = true;
            break;
        }
        case PROTOCOL_IPV6_FRAG: {
            uint16_t offset_flags = toHost16(wire.fragment.offset_flags, endian);
            header.fragment_offset = offset_flags >> 3;
            header.more_fragments = offset_flags & 0x1;
            header.identification = toHost32(wire.fragment.identification, endian);
            break;
        }
        case PROTOCOL_AH:
            header.spi = toHost32(wire.ah.spi, endian);
            break;
        default:
            break;
    }

    span = span.subspan(length);
    return ParseError::None;
}

ip::v6::Header pseudoHeader(const ip::v6::Header& ip_header, std::span<const Header> exts, size_t upper_len) noexcept {
    ip::v6::Header out = ip_header;
    out.payload_length = static_cast<uint16_t>(upper_len);
    if (!exts.empty()) out.next_header = exts.back().next_header;
    for (const Header& ext : exts) {
        if (ext.has_final_dst) std::memcpy(out.dst_ip, ext.final_dst, 16);
    }
    return out;
}

std::string Header::toString() const noexcept {
    std::ostringstream oss;
    oss << "IPv6ExtHeader {\n"
        << "  type: " << static_cast<int>(type) << " (" << ip::protocolName(type) << ")\n"
        << "  next_header: " << static_cast<int>(next_header) << " (" << ip::protocolName(next_header) << ")\n"
        << "  length: " << length << '\n';
    switch (type) {
        case PROTOCOL_IPV6_ROUTE:
            oss << "  routing_type: " << static_cast<int>(routing_type) << '\n'
                << "  segments_left: " << static_cast<int>(segments_left) << '\n';
            if (has_final_dst) {
                oss << "  final_dst: "; printIp(oss, final_dst); oss << '\n';
            }
            break;
        case PROTOCOL_IPV6_FRAG:
            oss << "  fragment_offset: " << fragment_offset << '\n'
                << "  more_fragments: " << (more_fragments ? "true" : "false") << '\n'
                << "  identification: 0x" << std::hex << std::setfill('0') << std::setw(8) << identification << std::dec << '\n';
            break;
        case PROTOCOL_AH:
            oss << "  spi: 0x" << std::hex << std::setfill('0') << std::setw(8) << spi << std::dec << '\n';
            break;
        default:
            break;
    }
    oss << "}";
    return oss.str();
}

std::string Header::toJson() const noexcept {
    std::ostringstream oss;
    oss << "\"ipv6_ext\": {\n"
        << "  \"type\": " << static_cast<int>(type) << ",\n"
        << "  \"name\": \"" << ip::protocolName(type) << "\",\n"
        << "  \"next_header\": " << static_cast<int>(next_header) << ",\n"
        << "  \"length\": " << length;
    switch (type) {
        case PROTOCOL_IPV6_ROUTE:
            oss << ",\n"
                << "  \"routing_type\": " << static_cast<int>(routing_type) << ",\n"
                << "  \"segments_left\": " << static_cast<int>(segments_left);
            if (has_final_dst) {
                oss << ",\n  \"final_dst\": \""; printIp(oss, final_dst); oss << '"';
            }
            break;
        case PROTOCOL_IPV6_FRAG:
            oss << ",\n"
                << "  \"fragment_offset\": " << fragment_offset << ",\n"
                << "  \"more_fragments\": " << (more_fragments ? "true" : "false") << ",\n"
                << "  \"identification\": \"0x" << std::hex << std::setfill('0') << std::setw(8) << identification << std::dec << '"';
            break;
        case PROTOCOL_AH:
            oss << ",\n"
                << "  \"spi\": \"0x" << std::hex << std::setfill('0') << std::setw(8) << spi << std::dec << '"';
            break;
        default:
            break;
    }
    oss << "\n}";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    return os << h.toString();
}

}
