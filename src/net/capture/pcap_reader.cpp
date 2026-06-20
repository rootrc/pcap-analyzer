#include <net/capture/pcap_reader.h>

namespace net::pcap {
    ParseError Reader::next(Packet& out) {
        if (fread(buffer_, 1, PACKET_HEADER_LEN, f_) != PACKET_HEADER_LEN) {
            return ParseError::UnexpectedEofF;
        }

        std::span<uint8_t> packet_header_view{buffer_, PACKET_HEADER_LEN };
                    
        ParseError err = parse(packet_header_view, out.record, endian_);
        if (err != ParseError::None) {
            return err;
        }

        out.raw.resize(out.record.incl_len);
        if (out.record.incl_len > 0) {
            if (fread(out.raw.data(), 1, out.record.incl_len, f_) != out.record.incl_len) {
                return ParseError::UnexpectedEofF;
            }
        }

        std::span<uint8_t> span{ out.raw.data(), out.raw.size() };
        return decodePacket(span, out);
    }

    [[nodiscard]] Packet::NetworkHeader Reader::networkFromEthertype(uint16_t ethertype) noexcept {
        switch (ethertype) {
            case ethernet::ETHERTYPE_IPV4: return ip::v4::Header{};
            case ethernet::ETHERTYPE_IPV6: return ip::v6::Header{};
            default: return std::monostate{};
        }
    }

    [[nodiscard]] Packet::TransportHeader Reader::transportFromProtocol(uint8_t protocol) noexcept {
        switch (protocol) {
            case ip::PROTOCOL_TCP: return tcp::Header{};
            case ip::PROTOCOL_UDP: return udp::Header{};
            default: return std::monostate{};
        }
    }

    ParseError Reader::readFileHeader() {
        if (fread(buffer_, 1, FILE_HEADER_LEN, f_) != FILE_HEADER_LEN)
            return ParseError::UnexpectedEofF;
        std::span<uint8_t> file_header_view{buffer_, FILE_HEADER_LEN};
        return parse(file_header_view, file_header_, endian_);
    }

    ParseError Reader::decodePacket(std::span<uint8_t>& span, Packet& out) {
        ParseError err = decodeLayer2(span, out);
        if (err != ParseError::None) {
            return err;
        }
        err = decodeLayer3(span, out);
        if (err != ParseError::None) {
            return err;
        }
        err = decodeLayer4(span, out);
        if (err != ParseError::None) {
            return err;
        }
        return ParseError::None;
    }

    ParseError Reader::decodeLayer2(std::span<uint8_t>& span, Packet& out) {
        ParseError err = ethernet::parse(span, out.eth, Endian::Big);
        if (err != ParseError::None) {
            return err;
        }
        out.network = networkFromEthertype(out.eth.ethertype);
        if (std::get_if<std::monostate>(&out.network) != nullptr) {
            return ParseError::UnsupportedNetworkType;
        }
        return ParseError::None;
    }

    ParseError Reader::decodeLayer3(std::span<uint8_t>& span, Packet& out) {
        return std::visit(overload{
            [&](ip::v4::Header& v4) -> ParseError {
                if (auto err = ip::v4::parse(span, v4, Endian::Big); err != ParseError::None) return err;
                out.transport = transportFromProtocol(v4.protocol);
                if (std::get_if<std::monostate>(&out.network) != nullptr) {
                    return ParseError::UnsupportedTransportType;
                }
                return ParseError::None;
            },
            [&](ip::v6::Header& v6) -> ParseError {
                if (auto err = ip::v6::parse(span, v6, Endian::Big); err != ParseError::None) return err;
                out.transport = transportFromProtocol(v6.next_header);
                if (std::get_if<std::monostate>(&out.network) != nullptr) {
                    return ParseError::UnsupportedTransportType;
                }
                return ParseError::None;
            },
            [&](std::monostate) -> ParseError { return ParseError::UnsupportedNetworkType; },
        }, out.network);
    }

    ParseError Reader::decodeLayer4(std::span<uint8_t>& span, Packet& out) {
        return std::visit(overload{
            [&](const auto& ip) -> ParseError {
                return std::visit(overload{
                    [&](tcp::Header& tcp) { return tcp::parse(span, tcp, ip, Endian::Big); },
                    [&](udp::Header& udp) { return udp::parse(span, udp, ip, Endian::Big); },
                    [&](std::monostate)   { return ParseError::UnsupportedTransportType; },
                }, out.transport);
            },
            [&](std::monostate) -> ParseError { return ParseError::UnsupportedNetworkType; },
        }, out.network);
    }

    void Reader::printNetwork(std::ostream& os, const Packet& out) const {
        std::visit([&](const auto& h) {
            using T = std::decay_t<decltype(h)>;

            if constexpr (std::is_same_v<T, std::monostate>) {
                os << "None";
            } else {
                os << h;
            }
        }, out.network);
        os << '\n';
    }

    void Reader::printTransport(std::ostream& os, const Packet& out) const {
        std::visit([&](const auto& h) {
            using T = std::decay_t<decltype(h)>;

            if constexpr (std::is_same_v<T, std::monostate>) {
                os << "None";
            } else {
                os << h;
            }
        }, out.transport);
        os << '\n';
    }
}