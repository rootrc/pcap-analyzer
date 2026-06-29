#include <net/capture/decoder.h>

namespace net::decode {

ParseError decodePacket(std::span<const uint8_t>& span, Packet& out) {
    if (auto err = decodeLayer2(span, out); err != ParseError::None) return err;
    if (auto err = decodeLayer3(span, out); err != ParseError::None) return err;
    if (out.isArp()) {
        return ParseError::None;
    }
    if (auto err = decodeLayer4(span, out); err != ParseError::None) return err;
    return ParseError::None;
}

ParseError decodeLayer2(std::span<const uint8_t>& span, Packet& out) {
    return std::visit(overload{
        [&](ethernet::Header& eth) -> ParseError {
            if (auto err = ethernet::parse(span, eth, Endian::Big); err != ParseError::None) return err;
            
            uint16_t ethertype = eth.ethertype;
            while (ethertype == ethernet::ETHERTYPE_VLAN || ethertype == ethernet::ETHERTYPE_VLAN_QQ) {
                vlan::Header vtag{};
                if (auto err = vlan::parse(span, vtag, Endian::Big); err != ParseError::None) return err;
                ethertype = vtag.ethertype;
                out.vlan_tags.push_back(vtag);
            }
            eth.ethertype = ethertype;
            
            out.setNetworkFromEthertype(eth.ethertype);
            return ParseError::None;
        },
        [&](std::monostate) -> ParseError { return ParseError::UnsupportedLinktype; },
    }, out.datalink);
}

ParseError decodeLayer3(std::span<const uint8_t>& span, Packet& out) {
    return std::visit(overload{
        [&](ip::v4::Header& v4) -> ParseError {
            if (auto err = ip::v4::parse(span, v4, Endian::Big); err != ParseError::None) return err;
            out.setTransportFromProtocol(v4.protocol);
            return ParseError::None;
        },
        [&](ip::v6::Header& v6) -> ParseError {
            if (auto err = ip::v6::parse(span, v6, Endian::Big); err != ParseError::None) return err;
            out.setTransportFromProtocol(v6.next_header);
            return ParseError::None;
        },
        [&](arp::Header& arp) -> ParseError {
            if (auto err = arp::parse(span, arp, Endian::Big); err != ParseError::None) return err;
            return ParseError::None;
        },
        [&](std::monostate) -> ParseError { return ParseError::UnsupportedNetworkType; },
    }, out.network);
}

ParseError decodeLayer4(std::span<const uint8_t>& span, Packet& out) {
    return std::visit(overload{
        [&](const ip::v4::Header& ip) -> ParseError {
            return std::visit(overload{
                [&](tcp::Header& h) { return tcp::parse(span, h, ip, Endian::Big); },
                [&](udp::Header& h) { return udp::parse(span, h, ip, Endian::Big); },
                [&](icmp::Header& h) { return icmp::parse(span, h, Endian::Big); },
                [&](icmpv6::Header&) { return ParseError::UnsupportedTransportType; },
                [&](std::monostate) { return ParseError::UnsupportedTransportType; },
            }, out.transport);
        },
        [&](const ip::v6::Header& ip) -> ParseError {
            return std::visit(overload{
                [&](tcp::Header& h) { return tcp::parse(span, h, ip, Endian::Big); },
                [&](udp::Header& h) { return udp::parse(span, h, ip, Endian::Big); },
                [&](icmp::Header&) { return ParseError::UnsupportedTransportType; },
                [&](icmpv6::Header& h) { return icmpv6::parse(span, h, ip, Endian::Big); },
                [&](std::monostate) { return ParseError::UnsupportedTransportType; },
            }, out.transport);
        },
        [&](const arp::Header& ) -> ParseError { return ParseError::None; },
        [&](std::monostate) -> ParseError { return ParseError::UnsupportedTransportType; },
    }, out.network);
}

}