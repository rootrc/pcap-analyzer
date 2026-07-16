#include <net/capture/pcap_reader.h>

namespace net::pcap {

void Reader::readAllPackets() {
    while (readPacket() == ParseError::None);
}

ParseError Reader::readPacket() {
    while (true) {
        if (fread(buffer_, 1, PACKET_HEADER_LEN, f_) != PACKET_HEADER_LEN) {
            flowTable_.flush();
            return ParseError::UnexpectedEofF;
        }

        std::span<const uint8_t> packet_header_span{buffer_, PACKET_HEADER_LEN};
        if (auto err = parse(packet_header_span, capture_.packetHeader, endian_); err != ParseError::None) {
            return err;
        }

        capture_.pkt.raw.resize(capture_.packetHeader.incl_len);
        if (fread(capture_.pkt.raw.data(), 1, capture_.packetHeader.incl_len, f_) != capture_.packetHeader.incl_len) {
            return ParseError::UnexpectedEofF;
        }
        capture_.pkt.setDatatypeFromLinktype(file_header_.linktype);

        if (is_nsec_) {
            capture_.ts_us = static_cast<uint64_t>(capture_.packetHeader.ts_sec) * 1000000 + capture_.packetHeader.ts_usec / 1000;
        } else {
            capture_.ts_us = static_cast<uint64_t>(capture_.packetHeader.ts_sec) * 1000000 + capture_.packetHeader.ts_usec;
        }

        std::span<const uint8_t> packet_span{capture_.pkt.raw.data(), capture_.pkt.raw.size()};
        if (auto err = decode::decodePacket(packet_span, capture_.pkt); err != ParseError::None) {
            ++skipped_;
            last_skip_err_ = err;
            continue;
        }
        if (auto err = flowTable_.addPacket(capture_.pkt, capture_.ts_us); err != ParseError::None) {
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