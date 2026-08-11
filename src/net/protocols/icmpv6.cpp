#include <net/protocols/icmpv6.h>
#include <net/util/checksum.h>

#include <cstring>
#include <iomanip>
#include <sstream>

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

std::string Header::toString() const noexcept {
    std::ostringstream oss;
    oss << "ICMPv6Header {\n"
        << "  type: " << static_cast<int>(type) << " (";
    switch (type) {
        case TYPE_UNREACHABLE: oss << "unreachable"; break;
        case TYPE_PACKET_TOO_BIG: oss << "packet too big"; break;
        case TYPE_TTL_EXCEEDED: oss << "TTL exceeded"; break;
        case TYPE_PARAM_PROBLEM: oss << "param problem"; break;
        case TYPE_ECHO_REQUEST: oss << "echo request"; break;
        case TYPE_ECHO_REPLY: oss << "echo reply"; break;
        default: oss << "unknown"; break;
    }
    oss << ")\n";
    switch (type) {
        case TYPE_UNREACHABLE:
            oss << "  code: " << static_cast<int>(code);
            switch (code) {
                case CODE_UNREACH_NO_ROUTE: oss << " (no route to destination)"; break;
                case CODE_UNREACH_ADMIN: oss << " (admin prohibited)"; break;
                case CODE_UNREACH_BEYOND_SCOPE: oss << " (beyond scope of source address)"; break;
                case CODE_UNREACH_ADDR: oss << " (address unreachable)"; break;
                case CODE_UNREACH_PORT: oss << " (port unreachable)"; break;
                default: break;
            }
            oss << '\n';
            break;
        case TYPE_TTL_EXCEEDED:
            oss << "  code: " << static_cast<int>(code);
            switch (code) {
                case CODE_TTL_IN_TRANSIT: oss << " (hop limit exceeded in transit)"; break;
                case CODE_TTL_REASSEMBLY: oss << " (fragment reassembly time exceeded)"; break;
                default: break;
            }
            oss << '\n';
            break;
        case TYPE_PARAM_PROBLEM:
            oss << "  code: " << static_cast<int>(code);
            switch (code) {
                case CODE_PARAM_BAD_HEADER: oss << " (erroneous header field)"; break;
                case CODE_PARAM_UNKNOWN_NEXT: oss << " (unrecognized next header)"; break;
                case CODE_PARAM_UNKNOWN_OPTION: oss << " (unrecognized option)"; break;
                default: break;
            }
            oss << '\n'
                << "  pointer: " << pointer << '\n';
            break;
        case TYPE_PACKET_TOO_BIG:
            oss << "  mtu: " << mtu << '\n';
            break;
        case TYPE_ECHO_REQUEST:
        case TYPE_ECHO_REPLY:
            oss << "  id: " << echo.id << '\n'
                << "  seq: " << echo.seq << '\n';
            break;
        default:
            break;
    }
    oss << "  checksum: 0x" << std::hex << std::setfill('0') << std::setw(4) << checksum << std::dec << '\n'
        << "}";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    return os << h.toString();
}

}