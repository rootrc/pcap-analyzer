#include <net/capture/pcap.h>

#include <cstring>
#include <sstream>

namespace net::pcap {

ParseError parse(std::span<const uint8_t>& span, FileHeader& header, Endian& endian) {
    if (span.size() < FILE_HEADER_LEN) return ParseError::UnexpectedEof;
    std::memcpy(&header, span.data(), FILE_HEADER_LEN);

    switch (header.magic_number) {
        case PCAP_MAGIC_USEC_BE:
            endian = Endian::Big;
            break;
        case PCAP_MAGIC_NSEC_BE:
            endian = Endian::Big;
            break;
        case PCAP_MAGIC_USEC_LE:
            endian = Endian::Little;
            break;
        case PCAP_MAGIC_NSEC_LE:
            endian = Endian::Little;
            break;
        default:
            return ParseError::InvalidFieldValue;
    }
    header.major_version = toHost16(header.major_version, endian);
    header.minor_version = toHost16(header.minor_version, endian);
    header.snaplen = toHost32(header.snaplen, endian);
    header.linktype = toHost32(header.linktype, endian);
    
    if (header.major_version != SUPPORTED_MAJOR_VERSION || header.minor_version != SUPPORTED_MINOR_VERSION) {
        return ParseError::UnsupportedVersion;
    }
    // if (header.reserved1 != 0 || header.reserved2 != 0) {
    //     return 0;
    // }
    if (header.snaplen == 0) {
        return ParseError::InvalidFieldValue;
    }
    if ((header.linktype & 0x0FFFFFFF) != LINKTYPE_ETHERNET) {
        return ParseError::UnsupportedLinktype;
    }
    span = span.subspan(FILE_HEADER_LEN);
    return ParseError::None;
}

ParseError parse(std::span<const uint8_t>& span, PacketHeader& header, Endian endian) {
    if (span.size() < PACKET_HEADER_LEN) return ParseError::UnexpectedEof;
    std::memcpy(&header, span.data(), PACKET_HEADER_LEN);

    header.ts_sec = toHost32(header.ts_sec, endian);
    header.ts_usec = toHost32(header.ts_usec, endian);
    header.incl_len = toHost32(header.incl_len, endian);
    header.orig_len = toHost32(header.orig_len, endian);

    if (header.incl_len == 0 || header.orig_len == 0) {
        return ParseError::InvalidFieldValue;
    }
    if (header.incl_len > header.orig_len) {
        return ParseError::MalformedHeader;
    }
    span = span.subspan(PACKET_HEADER_LEN);
    return ParseError::None;
}

std::string FileHeader::toString() const noexcept {
    std::ostringstream oss;
    oss << "FileHeader {\n"
        << "  magic: 0x" << std::hex << magic_number << std::dec << '\n'
        << "  version: " << major_version << "." << minor_version << '\n'
        << "  snaplen: " << snaplen << '\n'
        << "  linktype: " << linktype << '\n'
        << "}";
    return oss.str();
}

std::string PacketHeader::toString() const noexcept {
    std::ostringstream oss;
    oss << "PacketHeader {\n"
        << "  ts_sec: " << ts_sec << '\n'
        << "  ts_usec: " << ts_usec << '\n'
        << "  incl_len: " << incl_len << '\n'
        << "  orig_len: " << orig_len << '\n'
        << "}";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const FileHeader& h) {
    return os << h.toString();
}

std::ostream& operator<<(std::ostream& os, const PacketHeader& h) {
    return os << h.toString();
}

}