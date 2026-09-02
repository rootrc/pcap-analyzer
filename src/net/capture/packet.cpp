#include <net/capture/packet.h>
#include <net/util/text.h>

#include <sstream>

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
    vlan_tags.clear();
    network = std::monostate{};
    transport = std::monostate{};
}

std::string Packet::toString() const noexcept {
    std::ostringstream oss;
    if (ethernet()) oss << *ethernet() << '\n';
    for (const net::vlan::Header& vlan: vlan_tags) {
        oss << vlan << "\n";
    }
    if (ipv4()) oss << *ipv4() << '\n';
    if (ipv6()) oss << *ipv6() << '\n';
    if (arp()) oss << *arp() << '\n';
    if (udp()) oss << *udp() << '\n';
    if (tcp()) oss << *tcp() << '\n';
    if (icmp()) oss << *icmp() << '\n';
    if (icmpv6()) oss << *icmpv6() << '\n';
    return oss.str();
}

std::string Packet::toJson() const noexcept {
    std::ostringstream oss;
    bool first = true;
    auto printProtocol = [&](const auto* value) {
        if (value) {
            if (!first) oss << ",\n";
            oss << util::indent(value->toJson(), "  ");
            first = false;
        }
    };

    oss << "\"packet\": {\n";
    printProtocol(ethernet());

    if (!vlan_tags.empty()) {
        if (!first) oss << ",\n";
        oss << "  \"vlan\": [\n";
        for (size_t i = 0; i < vlan_tags.size(); ++i) {
            if (i) oss << ",\n";
            oss << util::indent(vlan_tags[i].toJson().erase(0, 8), "    ");
        }
        oss << "\n  ]";
        first = false;
    }

    printProtocol(ipv4());
    printProtocol(ipv6());
    printProtocol(arp());
    printProtocol(udp());
    printProtocol(tcp());
    printProtocol(icmp());
    printProtocol(icmpv6());

    if (!first) oss << '\n';
    oss << "}\n";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const Packet& pkt) {
    return os << pkt.toString();
}

}