#include <net/capture/pcap_reader.h>

namespace net::pcap {
    bool Reader::next(Packet& out) {
        if (fread(buffer_, 1, PACKET_HEADER_LEN, f_) != PACKET_HEADER_LEN) {
            return false;
        }
        
        BufferView packet_header_view{buffer_, PACKET_HEADER_LEN };
        if (parse(packet_header_view, out.record, endian_) == 0) {
            return false;
        }

        out.raw.resize(out.record.incl_len);
        if (out.record.incl_len > 0) {
            size_t nr = fread(out.raw.data(), 1, out.record.incl_len, f_);
            if (nr != out.record.incl_len) {
                return false;
            }
        }
        BufferView buf{ out.raw.data(), out.raw.size() };
        decodePacket(buf, out);
        return true;
    }

    bool Reader::readFileHeader() {
        if (fread(buffer_, 1, FILE_HEADER_LEN, f_) != FILE_HEADER_LEN)
            return false;
        BufferView file_header_view{buffer_, FILE_HEADER_LEN};
        return parse(file_header_view, file_header_, endian_) != 0;
    }

    bool Reader::decodePacket(BufferView& buf, Packet& out) {
        if (ethernet::parse(buf, out.eth, Endian::Big) == 0) {
            return false;
        }
        
        if (decodeLayer3(buf, out) == 0) {
            return false;
        }
        if (decodeLayer4(buf, out) == 0) {
            return false;
        }
        return true;
    }

    bool Reader::decodeLayer3(BufferView& buf, Packet& out) {
        switch (out.eth.ethertype) {
            case ethernet::ETHERTYPE_IPV4:
                if (ip::v4::parse(buf, out.ipv4, Endian::Big) == 0) {
                    return false;
                }
                out.network = Packet::NetworkType::IPv4;
                out.transport = transportFromProtocol(out.ipv4.protocol);
                break;
            case ethernet::ETHERTYPE_IPV6:
                if (ip::v6::parse(buf, out.ipv6, Endian::Big) == 0) {
                    return false;
                }
                out.network = Packet::NetworkType::IPv6;
                out.transport = transportFromProtocol(out.ipv6.next_header);
                break;
            
            default:
                return false;
        }
        return true;
    }

    bool Reader::decodeLayer4(BufferView& buf, Packet& out) {
        auto parse = [&](auto& ip) {
            switch (out.transport) {
                case Packet::TransportType::TCP:
                    if (tcp::parse(buf, out.tcp, ip, Endian::Big) == 0) {
                        return false;
                    }
                    
                    break;
                case Packet::TransportType::UDP:
                    if (udp::parse(buf, out.udp, ip, Endian::Big) == 0) {
                        return false;
                    }
                    break;
                
                default:
                    return false;
            }
            return true;
        };

        if (out.network == Packet::NetworkType::IPv4) {
            parse(out.ipv4);
        } else if (out.network == Packet::NetworkType::IPv6) {
            parse(out.ipv6);
        }
        return true;
    }
}