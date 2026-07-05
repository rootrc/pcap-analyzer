#include <net/capture/pcap_reader.h>

namespace net::pcap {

ParseError Reader::next(Capture& out) {
    while (true) {
        if (fread(buffer_, 1, PACKET_HEADER_LEN, f_) != PACKET_HEADER_LEN) {
            return ParseError::UnexpectedEofF;
        }

        std::span<const uint8_t> packet_header_span{buffer_, PACKET_HEADER_LEN};
        if (auto err = parse(packet_header_span, out.packetHeader, endian_); err != ParseError::None) {
            return err;
        }

        out.pkt.raw.resize(out.packetHeader.incl_len);
        if (fread(out.pkt.raw.data(), 1, out.packetHeader.incl_len, f_) != out.packetHeader.incl_len) {
            return ParseError::UnexpectedEofF;
        }
        out.pkt.setDatatypeFromLinktype(file_header_.linktype);

        if (is_nsec_) {
            out.ts_us = (uint64_t)out.packetHeader.ts_sec * 1000000 + out.packetHeader.ts_usec / 1000;
        } else {
            out.ts_us = (uint64_t)out.packetHeader.ts_sec * 1000000 + out.packetHeader.ts_usec;
        }

        std::span<const uint8_t> packet_span{out.pkt.raw.data(), out.pkt.raw.size()};
        if (auto err = decode::decodePacket(packet_span, out.pkt); err != ParseError::None) {
            ++skipped_;
            last_skip_err_ = err;
            continue;
        }

        return ParseError::None;
    }
}

ParseError Reader::readFileHeader() {
    if (fread(buffer_, 1, FILE_HEADER_LEN, f_) != FILE_HEADER_LEN)
        return ParseError::UnexpectedEofF;
    std::span<const uint8_t> file_header_span{buffer_, FILE_HEADER_LEN};
    if (auto err = parse(file_header_span, file_header_, endian_); err != ParseError::None) return err;
    is_nsec_ = (file_header_.magic_number == PCAP_MAGIC_NSEC_LE || file_header_.magic_number == PCAP_MAGIC_NSEC_BE);
    return ParseError::None;
}

}