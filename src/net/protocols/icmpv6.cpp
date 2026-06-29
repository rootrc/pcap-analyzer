#include <net/protocols/icmpv6.h>
#include <net/core/checksum.h>

#include <cstring>
#include <iomanip>

namespace net::icmpv6 {

ParseError parse(std::span<const uint8_t>& span, Header& header, const ip::v6::Header& ip_header, Endian endian) {
    if (span.size() < HEADER_LEN) return ParseError::UnexpectedEof;
    std::memcpy(&header, span.data(), HEADER_LEN);

    if (span.size() < ip_header.payload_length) {
        return ParseError::MalformedHeader;
    }

    header.checksum = toHost16(header.checksum, endian);

    switch (header.type) {
        case TYPE_ECHO_REQUEST:
        case TYPE_ECHO_REPLY:
        case TYPE_PACKET_TOO_BIG:
        case TYPE_ROUTER_SOLICIT:
        case TYPE_ROUTER_ADVERT:
        case TYPE_NEIGHBOR_SOLICIT:
        case TYPE_NEIGHBOR_ADVERT:
            if (header.code != 0) return ParseError::InvalidFieldValue;
            break;
        case TYPE_UNREACHABLE:
            if (header.code > CODE_UNREACH_PORT) return ParseError::InvalidFieldValue;
            break;
        case TYPE_TTL_EXCEEDED:
            if (header.code > CODE_TTL_REASSEMBLY) return ParseError::InvalidFieldValue;
            break;
        case TYPE_PARAM_PROBLEM:
            if (header.code > CODE_PARAM_UNKNOWN_OPTION) return ParseError::InvalidFieldValue;
            break;
        default:
            return ParseError::InvalidFieldValue;
    }
    if (header.type == TYPE_PACKET_TOO_BIG) {
        header.mtu = toHost32(header.mtu, endian);
        if (header.mtu < MIN_MTU) return ParseError::InvalidFieldValue;
    } else if (header.type == TYPE_PARAM_PROBLEM) {
        header.pointer = toHost32(header.pointer, endian);
    } else if (header.type == TYPE_ECHO_REQUEST || header.type == TYPE_ECHO_REPLY) {
        header.echo.id = toHost16(header.echo.id, endian);
        header.echo.seq = toHost16(header.echo.seq, endian);
    }
    if (!verifyChecksum(span.data(), ip_header.payload_length, ip::v6::computePseudoHeaderSum(ip_header))) {
        return ParseError::ChecksumMismatch;
    }

    span = span.subspan(HEADER_LEN);
    return ParseError::None;
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    os << "ICMPv6Header {\n"
        << "  type: " << static_cast<int>(h.type) << " (";
    switch (h.type) {
        case TYPE_UNREACHABLE: os << "unreachable"; break;
        case TYPE_PACKET_TOO_BIG: os << "packet too big"; break;
        case TYPE_TTL_EXCEEDED: os << "TTL exceeded"; break;
        case TYPE_PARAM_PROBLEM: os << "param problem"; break;
        case TYPE_ECHO_REQUEST: os << "echo request"; break;
        case TYPE_ECHO_REPLY: os << "echo reply"; break;
        default: os << "unknown"; break;
    }
    os << ")\n";
    switch (h.type) {
        case TYPE_UNREACHABLE:
            os << "  code: " << static_cast<int>(h.code);
            switch (h.code) {
                case CODE_UNREACH_NO_ROUTE: os << " (no route to destination)"; break;
                case CODE_UNREACH_ADMIN: os << " (admin prohibited)"; break;
                case CODE_UNREACH_BEYOND_SCOPE: os << " (beyond scope of source address)"; break;
                case CODE_UNREACH_ADDR: os << " (address unreachable)"; break;
                case CODE_UNREACH_PORT: os << " (port unreachable)"; break;
                default: break;
            }
            os << '\n';
            break;
        case TYPE_TTL_EXCEEDED:
            os << "  code: " << static_cast<int>(h.code);
            switch (h.code) {
                case CODE_TTL_IN_TRANSIT: os << " (hop limit exceeded in transit)"; break;
                case CODE_TTL_REASSEMBLY: os << " (fragment reassembly time exceeded)"; break;
                default: break;
            }
            os << '\n';
            break;
        case TYPE_PARAM_PROBLEM:
            os << "  code: " << static_cast<int>(h.code);
            switch (h.code) {
                case CODE_PARAM_BAD_HEADER: os << " (erroneous header field)"; break;
                case CODE_PARAM_UNKNOWN_NEXT: os << " (unrecognized next header)"; break;
                case CODE_PARAM_UNKNOWN_OPTION: os << " (unrecognized option)"; break;
                default: break;
            }
            os << '\n';
            os << "  pointer: " << h.pointer << '\n';
            break;
        case TYPE_PACKET_TOO_BIG:
            os << "  mtu: " << h.mtu << '\n';
            break;
        case TYPE_ECHO_REQUEST:
        case TYPE_ECHO_REPLY:
            os << "  id: " << h.echo.id << '\n'
               << "  seq: " << h.echo.seq << '\n';
            break;
        default:
            break;
    }
    os << "  checksum: 0x" << std::hex << std::setfill('0') << std::setw(4) << h.checksum << std::dec << '\n';
    os << "}";
    return os;
}

}