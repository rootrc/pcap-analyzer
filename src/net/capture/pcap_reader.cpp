#include <net/capture/pcap_reader.h>

namespace net::pcap {

ParseError Reader::next(Capture& out) {
    while (true) {
        if (fread(buffer_, 1, PACKET_HEADER_LEN, f_) != PACKET_HEADER_LEN) {
            return ParseError::UnexpectedEofF;
        }
        std::span<const uint8_t> span{buffer_, PACKET_HEADER_LEN};
        if (auto err = parse(span, out.packetHeader, endian_); err != ParseError::None) return err;

        out.pkt.raw.resize(out.packetHeader.incl_len);
        if (fread(out.pkt.raw.data(), 1, out.packetHeader.incl_len, f_) != out.packetHeader.incl_len) {
            return ParseError::UnexpectedEofF;
        }
        out.pkt.setDatatypeFromLinktype(file_header_.linktype);

        span = {out.pkt.raw.data(), out.pkt.raw.size()};
        if (auto err = decode::decodePacket(span, out.pkt); err != ParseError::None) {
            ++skipped_;
            last_skip_err_ = err;
            continue;
        }
        return ParseError::None;
    }
}

void Reader::printNetwork(std::ostream& os, const Capture& capture) const {
    std::visit([&](const auto& h) {
        using T = std::decay_t<decltype(h)>;

        if constexpr (std::is_same_v<T, std::monostate>) {
            os << "None";
        } else {
            os << h;
        }
    }, capture.pkt.network);
    os << '\n';
}

void Reader::printTransport(std::ostream& os, const Capture& capture) const {
    std::visit([&](const auto& h) {
        using T = std::decay_t<decltype(h)>;

        if constexpr (std::is_same_v<T, std::monostate>) {
            os << "None";
        } else {
            os << h;
        }
    }, capture.pkt.transport);
    os << '\n';
}

ParseError Reader::readFileHeader() {
    if (fread(buffer_, 1, FILE_HEADER_LEN, f_) != FILE_HEADER_LEN)
        return ParseError::UnexpectedEofF;
    std::span<const uint8_t> span{buffer_, FILE_HEADER_LEN};
    return parse(span, file_header_, endian_);
}

}