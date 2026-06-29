#include <net/protocols/icmp.h>
#include <net/protocols/ipv4.h>
#include <net/core/checksum.h>


#include <cstring>
#include <iomanip>

namespace net::icmp {
    
ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian) {
    if (span.size() < HEADER_LEN) return ParseError::UnexpectedEof;
    std::memcpy(&header, span.data(), HEADER_LEN);

    switch (header.type) {
        case TYPE_ECHO_REQUEST:
        case TYPE_ECHO_REPLY:
        case TYPE_SOURCE_QUENCH:
        case TYPE_TIMESTAMP:
        case TYPE_TIMESTAMP_REPLY:
        case TYPE_INFO_REQUEST:
        case TYPE_INFO_REPLY:
            if (header.code != 0) return ParseError::InvalidFieldValue;
            break;
        case TYPE_UNREACHABLE:
            if (header.code > 15) return ParseError::InvalidFieldValue;
            break;
        case TYPE_REDIRECT:
            if (header.code > CODE_REDIRECT_TOS_HOST) return ParseError::InvalidFieldValue;
            break;
        case TYPE_TTL_EXCEEDED:
            if (header.code > CODE_TTL_REASSEMBLY) return ParseError::InvalidFieldValue;
            break;
        case TYPE_PARAM_PROBLEM:
            if (header.code > CODE_PARAM_MISSING_OPT) return ParseError::InvalidFieldValue;
            break;
        default:
            return ParseError::InvalidFieldValue;
    }
    if (header.type == TYPE_REDIRECT) {
        header.gateway = toHost32(header.gateway, endian);
    } else if (header.type == TYPE_ECHO_REQUEST || header.type == TYPE_ECHO_REPLY) {
        header.echo.id = toHost16(header.echo.id, endian);
        header.echo.seq = toHost16(header.echo.seq, endian);
    }
    if (!verifyChecksum(span.data(), span.size())) {
        return ParseError::ChecksumMismatch;
    }
    header.checksum = toHost16(header.checksum, endian);

    span = span.subspan(HEADER_LEN);
    return ParseError::None;
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    os << "ICMPHeader {\n"
        << "  type: " << static_cast<int>(h.type) << " (";
    switch (h.type) {
        case TYPE_ECHO_REPLY: os << "echo reply"; break;
        case TYPE_UNREACHABLE: os << "unreachable"; break;
        case TYPE_SOURCE_QUENCH: os << "source quench"; break;
        case TYPE_REDIRECT: os << "redirect"; break;
        case TYPE_ECHO_REQUEST: os << "echo request"; break;
        case TYPE_TTL_EXCEEDED: os << "TTL exceeded"; break;
        case TYPE_PARAM_PROBLEM: os << "param problem"; break;
        case TYPE_TIMESTAMP: os << "timestamp"; break;
        case TYPE_TIMESTAMP_REPLY: os << "timestamp reply"; break;
        case TYPE_INFO_REQUEST: os << "info request"; break;
        case TYPE_INFO_REPLY: os << "info reply"; break;
        default: os << "unknown"; break;
    }
    os << ")\n";
    switch (h.type) {
        case TYPE_UNREACHABLE:
            os << "  code: " << static_cast<int>(h.code);
            switch (h.code) {
                case CODE_NET_UNREACHABLE: os << " (net unreachable)"; break;
                case CODE_HOST_UNREACHABLE: os << " (host unreachable)"; break;
                case CODE_PORT_UNREACHABLE: os << " (port unreachable)"; break;
                default: break;
            }
            os << '\n';
            break;
        case TYPE_REDIRECT:
            os << "  code: " << static_cast<int>(h.code);
            switch (h.code) {
                case CODE_REDIRECT_NET: os << " (redirect for network)"; break;
                case CODE_REDIRECT_HOST: os << " (redirect for host)"; break;
                case CODE_REDIRECT_TOS_NET: os << " (redirect for TOS and network)"; break;
                case CODE_REDIRECT_TOS_HOST: os << " (redirect for TOS and host)"; break;
                default: break;
            }
            os << '\n';
            os << "  gateway: ";
            ip::v4::printIp(os, h.gateway);
            os << '\n';
            break;
        case TYPE_TTL_EXCEEDED:
            os << "  code: " << static_cast<int>(h.code);
            switch (h.code) {
                case CODE_TTL_IN_TRANSIT: os << " (TTL exceeded in transit)"; break;
                case CODE_TTL_REASSEMBLY: os << " (fragment reassembly exceeded)"; break;
                default: break;
            }
            os << '\n';
            break;
        case TYPE_PARAM_PROBLEM:
            os << "  code: " << static_cast<int>(h.code);
            switch (h.code) {
                case CODE_PARAM_BAD_HEADER: os << " (bad header)"; break;
                case CODE_PARAM_MISSING_OPT: os << " (missing option)"; break;
                default: break;
            }
            os << '\n';
            os << "  pointer: " << static_cast<int>(h.param_problem.pointer) << '\n';
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