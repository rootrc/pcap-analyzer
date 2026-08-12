#pragma once

#include <net/capture/pcap.h>
#include <net/protocols/protocols.h>

#include <string>
#include <variant>
#include <vector>

namespace net {

struct Packet {
    // Layer 2
    using DataLinkHeader = std::variant<
        std::monostate,
        ethernet::Header
    >;
    DataLinkHeader datalink{};

    // Layer 2.5
    std::vector<vlan::Header> vlan_tags;

    // Layer 3
    using NetworkHeader = std::variant<
        std::monostate,
        ip::v4::Header,
        ip::v6::Header,
        arp::Header
    >;
    NetworkHeader network{};

    // Layer 4
    using TransportHeader = std::variant<
        std::monostate,
        tcp::Header,
        udp::Header,
        icmp::Header,
        icmpv6::Header
    >;
    TransportHeader transport{};

    std::span<const uint8_t> payload;

    [[nodiscard]] bool isEthernet() const noexcept { return std::holds_alternative<ethernet::Header>(datalink); }
    [[nodiscard]] bool isVlan() const noexcept { return !vlan_tags.empty(); }
    [[nodiscard]] bool isIpv4() const noexcept { return std::holds_alternative<ip::v4::Header>(network); }
    [[nodiscard]] bool isIpv6() const noexcept { return std::holds_alternative<ip::v6::Header>(network); }
    [[nodiscard]] bool isArp() const noexcept { return std::holds_alternative<arp::Header>(network); }
    [[nodiscard]] bool isTcp() const noexcept { return std::holds_alternative<tcp::Header>(transport); }
    [[nodiscard]] bool isUdp() const noexcept { return std::holds_alternative<udp::Header>(transport); }
    [[nodiscard]] bool isIcmp() const noexcept { return std::holds_alternative<icmp::Header>(transport); }
    [[nodiscard]] bool isIcmpv6() const noexcept { return std::holds_alternative<icmpv6::Header>(transport); }

    [[nodiscard]] const ethernet::Header* ethernet() const noexcept { return std::get_if<ethernet::Header>(&datalink); }
    [[nodiscard]] const std::vector<vlan::Header>& vlan() const noexcept { return vlan_tags; }
    [[nodiscard]] const ip::v4::Header* ipv4() const noexcept { return std::get_if<ip::v4::Header>(&network); }
    [[nodiscard]] const ip::v6::Header* ipv6() const noexcept { return std::get_if<ip::v6::Header>(&network); }
    [[nodiscard]] const arp::Header* arp() const noexcept { return std::get_if<arp::Header>(&network); }
    [[nodiscard]] const tcp::Header* tcp() const noexcept { return std::get_if<tcp::Header>(&transport); }
    [[nodiscard]] const udp::Header* udp() const noexcept { return std::get_if<udp::Header>(&transport); }
    [[nodiscard]] const icmp::Header* icmp() const noexcept { return std::get_if<icmp::Header>(&transport); }
    [[nodiscard]] const icmpv6::Header* icmpv6() const noexcept { return std::get_if<icmpv6::Header>(&transport); }
    
    void setDatatypeFromLinktype(uint32_t linktype) noexcept;
    void setNetworkFromEthertype(uint16_t ethertype) noexcept;
    void setTransportFromProtocol(uint8_t protocol) noexcept;
    void reset() noexcept;

    std::string toString() const noexcept;
};

std::ostream& operator<<(std::ostream& os, const Packet& pkt);

}