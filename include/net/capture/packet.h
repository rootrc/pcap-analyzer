
#pragma once

#include <net/capture/pcap.h>
#include <net/protocols/protocols.h>

#include <vector>
#include <variant>

namespace net::pcap {

struct Packet {
    PacketHeader record{};

    ethernet::Header eth{};

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

    [[nodiscard]] bool isIpv4() const noexcept { return std::holds_alternative<ip::v4::Header>(network); }
    [[nodiscard]] bool isIpv6() const noexcept { return std::holds_alternative<ip::v6::Header>(network); }
    [[nodiscard]] bool isTcp() const noexcept { return std::holds_alternative<tcp::Header>(transport); }
    [[nodiscard]] bool isUdp() const noexcept { return std::holds_alternative<udp::Header>(transport); }

    [[nodiscard]] const ip::v4::Header* ipv4() const noexcept { return std::get_if<ip::v4::Header>(&network); }
    [[nodiscard]] const ip::v6::Header* ipv6() const noexcept { return std::get_if<ip::v6::Header>(&network); }
    [[nodiscard]] const tcp::Header* tcp() const noexcept { return std::get_if<tcp::Header>(&transport); }
    [[nodiscard]] const udp::Header* udp() const noexcept { return std::get_if<udp::Header>(&transport); }
    
    void reset() noexcept {
        eth = {};
        network = std::monostate{};
        transport = std::monostate{};
        record = {};
        raw.clear();
    }
};

}