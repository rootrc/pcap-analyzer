#pragma once

#include <net/capture/pcap.h>
#include <net/protocols/protocols.h>

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
        ip::v6::Header
    >;
    NetworkHeader network{};

    // Layer 4
    using TransportHeader = std::variant<
        std::monostate,
        tcp::Header,
        udp::Header
    >;
    TransportHeader transport{};

    std::vector<uint8_t> raw;

    [[nodiscard]] bool isEthernet() const noexcept { return std::holds_alternative<ethernet::Header>(datalink); }
    [[nodiscard]] bool isVlan() const noexcept { return !vlan_tags.empty(); }
    [[nodiscard]] bool isIpv4() const noexcept { return std::holds_alternative<ip::v4::Header>(network); }
    [[nodiscard]] bool isIpv6() const noexcept { return std::holds_alternative<ip::v6::Header>(network); }
    [[nodiscard]] bool isTcp() const noexcept { return std::holds_alternative<tcp::Header>(transport); }
    [[nodiscard]] bool isUdp() const noexcept { return std::holds_alternative<udp::Header>(transport); }

    [[nodiscard]] const ethernet::Header* ethernet() const noexcept { return std::get_if<ethernet::Header>(&datalink); }
    [[nodiscard]] const std::vector<vlan::Header>& vlan() const noexcept { return vlan_tags; }
    [[nodiscard]] const ip::v4::Header* ipv4() const noexcept { return std::get_if<ip::v4::Header>(&network); }
    [[nodiscard]] const ip::v6::Header* ipv6() const noexcept { return std::get_if<ip::v6::Header>(&network); }
    [[nodiscard]] const tcp::Header* tcp() const noexcept { return std::get_if<tcp::Header>(&transport); }
    [[nodiscard]] const udp::Header* udp() const noexcept { return std::get_if<udp::Header>(&transport); }
    
    void setDatatypeFromLinktype(uint32_t linktype) noexcept {
        switch (linktype) {
            case pcap::LINKTYPE_ETHERNET: datalink = ethernet::Header{}; return;
            default: datalink = std::monostate{}; return;
        }
    }

    void setNetworkFromEthertype(uint16_t ethertype) noexcept {
        switch (ethertype) {
            case ethernet::ETHERTYPE_IPV4: network = ip::v4::Header{}; return;
            case ethernet::ETHERTYPE_IPV6: network = ip::v6::Header{}; return;
            default: network = std::monostate{}; return;
        }
    }

    void setTransportFromProtocol(uint8_t protocol) noexcept {
        switch (protocol) {
            case ip::PROTOCOL_TCP: transport = tcp::Header{}; return;
            case ip::PROTOCOL_UDP: transport = udp::Header{}; return;
            default: transport = std::monostate{}; return;
        }
    }

    void reset() noexcept {
        datalink = std::monostate{};
        vlan_tags.clear();
        network = std::monostate{};
        transport = std::monostate{};
        raw.clear();
    }
};

}