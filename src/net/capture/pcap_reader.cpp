#include <net/capture/pcap_reader.h>

namespace net::pcap {
    ParseError Reader::next(Packet& out) {
        if (fread(buffer_, 1, PACKET_HEADER_LEN, f_) != PACKET_HEADER_LEN) {
            return ParseError::UnexpectedEofF;
        }

        BufferView packet_header_view{buffer_, PACKET_HEADER_LEN };
                    
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

        BufferView buf{ out.raw.data(), out.raw.size() };
        decodePacket(buf, out);
        return ParseError::None;
    }

    Packet::TransportType Reader::transportFromProtocol(uint8_t protocal) {
        switch (protocal) {
            case ip::PROTOCOL_TCP: return Packet::TransportType::TCP;
            case ip::PROTOCOL_UDP: return Packet::TransportType::UDP;
            default: return Packet::TransportType::None;
        }
    }

    ParseError Reader::readFileHeader() {
        if (fread(buffer_, 1, FILE_HEADER_LEN, f_) != FILE_HEADER_LEN)
            return ParseError::UnexpectedEofF;
        BufferView file_header_view{buffer_, FILE_HEADER_LEN};
        return parse(file_header_view, file_header_, endian_);
    }

    ParseError Reader::decodePacket(BufferView& buf, Packet& out) {
        ParseError err = ethernet::parse(buf, out.eth, Endian::Big);
        if (err != ParseError::None) {
            return err;
        }
        err = decodeLayer3(buf, out);
        if (err != ParseError::None) {
            return err;
        }
        err = decodeLayer4(buf, out);
        if (err != ParseError::None) {
            return err;
        }
        return ParseError::None;
    }

    ParseError Reader::decodeLayer3(BufferView& buf, Packet& out) {
        ParseError err;
        switch (out.eth.ethertype) {
            case ethernet::ETHERTYPE_IPV4:
                    err = ip::v4::parse(buf, out.ipv4, Endian::Big);
                if (err != ParseError::None) {
                    return err;
                }
                out.network = Packet::NetworkType::IPv4;
                out.transport = transportFromProtocol(out.ipv4.protocol);
                break;  
            case ethernet::ETHERTYPE_IPV6:
                    err = ip::v6::parse(buf, out.ipv6, Endian::Big);
                if (err != ParseError::None) {
                    return err;
                }
                out.network = Packet::NetworkType::IPv6;
                out.transport = transportFromProtocol(out.ipv6.next_header);
                break;
            default:
                return ParseError::UnsupportedNetworkType;
        }
        return ParseError::None;
    }

    ParseError Reader::decodeLayer4(BufferView& buf, Packet& out) {
        auto parse = [&](auto& ip) {
            switch (out.transport) {
                case Packet::TransportType::TCP:
                    return tcp::parse(buf, out.tcp, ip, Endian::Big);
                case Packet::TransportType::UDP:
                    return udp::parse(buf, out.udp, ip, Endian::Big);
                default:
                    return ParseError::UnsupportedTransportType;
            }
        };

        if (out.network == Packet::NetworkType::IPv4) {
            ParseError err = parse(out.ipv4);
            if (err != ParseError::None) {
                return err;
            }
        } else if (out.network == Packet::NetworkType::IPv6) {
            ParseError err = parse(out.ipv6);
            if (err != ParseError::None) {
                return err;
            }
        }
        return ParseError::None;
    }
}