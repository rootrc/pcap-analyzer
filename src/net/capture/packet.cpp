#include <net/capture/packet.h>

namespace net {

void Packet::setDatatypeFromLinktype(uint32_t linktype) noexcept {
    switch (linktype) {
        case pcap::LINKTYPE_ETHERNET: datalink = ethernet::Header{}; return;
        default: datalink = std::monostate{}; return;
    }
}

void Packet::setNetworkFromEthertype(uint16_t ethertype) noexcept {
    switch (ethertype) {
        case ethernet::ETHERTYPE_IPV4: network = ip::v4::Header{}; return;
        case ethernet::ETHERTYPE_IPV6: network = ip::v6::Header{}; return;
        case ethernet::ETHERTYPE_ARP: network = arp::Header{}; return;
        default: network = std::monostate{}; return;
    }
}

void Packet::setTransportFromProtocol(uint8_t protocol) noexcept {
    switch (protocol) {
        case ip::PROTOCOL_TCP: transport = tcp::Header{}; return;
        case ip::PROTOCOL_UDP: transport = udp::Header{}; return;
        case ip::PROTOCOL_ICMP: transport = icmp::Header{}; return;
        case ip::PROTOCOL_ICMPV6: transport = icmpv6::Header{}; return;
        default: transport = std::monostate{}; return;
    }
}

void Packet::reset() noexcept {
    datalink = std::monostate{};
    vlan_tags.clear();
    network = std::monostate{};
    transport = std::monostate{};
    raw.clear();
}

std::ostream& operator<<(std::ostream& os, const Packet& pkt) {
    if (pkt.ethernet()) os << *pkt.ethernet() << '\n';
    for (const net::vlan::Header& vlan: pkt.vlan_tags) {
        os << vlan << "\n";
    }
    if (pkt.ipv4()) os << *pkt.ipv4() << '\n';
    if (pkt.ipv6()) os << *pkt.ipv6() << '\n';
    if (pkt.arp()) os << *pkt.arp() << '\n';
    if (pkt.udp()) os << *pkt.udp() << '\n';
    if (pkt.tcp()) os << *pkt.tcp() << '\n';
    if (pkt.icmp()) os << *pkt.icmp() << '\n';
    if (pkt.icmpv6()) os << *pkt.icmpv6() << '\n';
    return os;
}

}