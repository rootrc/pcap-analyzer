#include <net/protocols/icmp.h>
#include <net/protocols/ipv4.h>
#include <net/util/checksum.h>

#include <cstring>
#include <iomanip>
#include <sstream>

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

std::string Header::toString() const noexcept {
    std::ostringstream oss;
    oss << "ICMPHeader {\n"
        << "  type: " << static_cast<int>(type) << " (";
    switch (type) {
        case TYPE_ECHO_REPLY: oss << "echo reply"; break;
        case TYPE_UNREACHABLE: oss << "unreachable"; break;
        case TYPE_SOURCE_QUENCH: oss << "source quench"; break;
        case TYPE_REDIRECT: oss << "redirect"; break;
        case TYPE_ECHO_REQUEST: oss << "echo request"; break;
        case TYPE_TTL_EXCEEDED: oss << "TTL exceeded"; break;
        case TYPE_PARAM_PROBLEM: oss << "param problem"; break;
        case TYPE_TIMESTAMP: oss << "timestamp"; break;
        case TYPE_TIMESTAMP_REPLY: oss << "timestamp reply"; break;
        case TYPE_INFO_REQUEST: oss << "info request"; break;
        case TYPE_INFO_REPLY: oss << "info reply"; break;
        default: oss << "unknown"; break;
    }
    oss << ")\n";
    switch (type) {
        case TYPE_UNREACHABLE:
            oss << "  code: " << static_cast<int>(code);
            switch (code) {
                case CODE_NET_UNREACHABLE: oss << " (net unreachable)"; break;
                case CODE_HOST_UNREACHABLE: oss << " (host unreachable)"; break;
                case CODE_PORT_UNREACHABLE: oss << " (port unreachable)"; break;
                default: break;
            }
            oss << '\n';
            break;
        case TYPE_REDIRECT:
            oss << "  code: " << static_cast<int>(code);
            switch (code) {
                case CODE_REDIRECT_NET: oss << " (redirect for network)"; break;
                case CODE_REDIRECT_HOST: oss << " (redirect for host)"; break;
                case CODE_REDIRECT_TOS_NET: oss << " (redirect for TOS and network)"; break;
                case CODE_REDIRECT_TOS_HOST: oss << " (redirect for TOS and host)"; break;
                default: break;
            }
            oss << '\n'
                << "  gateway: "; ip::v4::printIp(oss, gateway); oss << '\n';
            break;
        case TYPE_TTL_EXCEEDED:
            oss << "  code: " << static_cast<int>(code);
            switch (code) {
                case CODE_TTL_IN_TRANSIT: oss << " (TTL exceeded in transit)"; break;
                case CODE_TTL_REASSEMBLY: oss << " (fragment reassembly exceeded)"; break;
                default: break;
            }
            oss << '\n';
            break;
        case TYPE_PARAM_PROBLEM:
            oss << "  code: " << static_cast<int>(code);
            switch (code) {
                case CODE_PARAM_BAD_HEADER: oss << " (bad header)"; break;
                case CODE_PARAM_MISSING_OPT: oss << " (missing option)"; break;
                default: break;
            }
            oss << '\n'
                << "  pointer: " << static_cast<int>(param_problem.pointer) << '\n';
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

std::string Header::toJson() const noexcept {
    std::ostringstream oss;
    oss << "\"icmp\": {\n"
        << "  \"type\": " << static_cast<int>(type) << ",\n"
        << "  \"code\": " << static_cast<int>(code) << ",\n";
    switch (type) {
        case TYPE_REDIRECT:
            oss << "  \"gateway\": \""; ip::v4::printIp(oss, gateway); oss << "\",\n";
            break;
        case TYPE_PARAM_PROBLEM:
            oss << "  \"pointer\": " << static_cast<int>(param_problem.pointer) << ",\n";
            break;
        case TYPE_ECHO_REQUEST:
        case TYPE_ECHO_REPLY:
            oss << "  \"id\": " << echo.id << ",\n"
                << "  \"seq\": " << echo.seq << ",\n";
            break;
        default:
            break;
    }
    oss << "  \"checksum\": \"0x" << std::hex << std::setfill('0') << std::setw(4) << checksum << std::dec << "\"\n"
        << "}";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    return os << h.toString();
}

}