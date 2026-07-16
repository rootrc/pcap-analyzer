#include "packet_generator.h"

#include <net/capture/pcap.h>

#include <cstring>

namespace testgen {

void makePcapFileHeader(uint8_t* data, net::Endian endian) {
    net::pcap::FileHeader h{};

    h.magic_number = (endian == net::Endian::Little) ? net::pcap::PCAP_MAGIC_USEC_LE : net::pcap::PCAP_MAGIC_USEC_BE;
    h.major_version = net::toHost16(net::pcap::SUPPORTED_MAJOR_VERSION, endian);
    h.minor_version = net::toHost16(net::pcap::SUPPORTED_MINOR_VERSION, endian);
    h.reserved1 = 0;
    h.reserved2 = 0;
    h.snaplen = net::toHost32(65535, endian);
    h.linktype = net::toHost32(net::pcap::LINKTYPE_ETHERNET, endian);
    memcpy(data, &h, net::pcap::FILE_HEADER_LEN);
}

void makePcapPacketHeader(uint8_t* data, uint32_t captured_len, net::Endian endian) {
    net::pcap::PacketHeader h{};

    h.ts_sec = randomgen::rand32();
    h.ts_usec = randomgen::rand32() % 1000000;
    h.orig_len = net::toHost32(captured_len, endian);
    h.incl_len = net::toHost32(captured_len, endian);
    memcpy(data, &h, net::pcap::PACKET_HEADER_LEN);
}

inline uint16_t getRandomNetwork(bool vlan = true) {
    constexpr uint16_t networks[] = {
        net::ethernet::ETHERTYPE_IPV4,
        net::ethernet::ETHERTYPE_IPV6,
        net::ethernet::ETHERTYPE_ARP,
        net::ethernet::ETHERTYPE_VLAN,
        net::ethernet::ETHERTYPE_VLAN_QQ,
    };
    if (vlan) {
        return networks[std::rand() % (sizeof(networks) / sizeof(networks[0]))];
    } else {
        return networks[std::rand() % ((sizeof(networks)) / sizeof(networks[0]) - 2)];
    }
}

inline uint8_t getRandomTransport(uint16_t network) {
    int random = std::rand();
    if (random % 3 == 0) {
        return net::ip::PROTOCOL_UDP;
    } else if (random % 3 == 1) {
        return net::ip::PROTOCOL_TCP;
    } else if (random % 3 == 2) {
        if (network == net::ethernet::ETHERTYPE_IPV4) {
            return net::ip::PROTOCOL_ICMP;
        } else if (network == net::ethernet::ETHERTYPE_IPV6) {
            return net::ip::PROTOCOL_ICMPV6;
        }
    }
    return 0;
}

void makePcapPacket(uint8_t* data, size_t total_length) {
    uint16_t network = getRandomNetwork();
    
    total_length -= net::pcap::PACKET_HEADER_LEN;
    testgen::makePcapPacketHeader(data, total_length);
    data += net::pcap::PACKET_HEADER_LEN;
    
    total_length -= net::ethernet::HEADER_LEN;
    testgen::makeEthernetHeader(data, network);
    data += net::ethernet::HEADER_LEN;
    
    if (network == net::ethernet::ETHERTYPE_VLAN_QQ) {
        network = net::ethernet::ETHERTYPE_VLAN;
        total_length -= net::vlan::HEADER_LEN;
        testgen::makeVlanHeader(data, network);
        data += net::vlan::HEADER_LEN;
    }
    if (network == net::ethernet::ETHERTYPE_VLAN) {
        network = getRandomNetwork(false);
        total_length -= net::vlan::HEADER_LEN;
        testgen::makeVlanHeader(data, network);
        data += net::vlan::HEADER_LEN;
    }

    uint8_t transport = getRandomTransport(network);
    
    net::ip::v4::Header ipv4_header{};
    net::ip::v6::Header ipv6_header{};
    if (network == net::ethernet::ETHERTYPE_IPV4) {
        size_t header_length = sizeof(uint32_t) * randomgen::randRange8(net::ip::v4::MIN_IHL, net::ip::v4::MAX_IHL);
        total_length -= header_length;
        testgen::makeIPv4Header(data, transport, header_length / sizeof(uint32_t), total_length);
        std::span<const uint8_t> span{data, static_cast<size_t>(header_length)};
        net::ip::v4::parse(span, ipv4_header, net::Endian::Big);
        data += header_length;
    } else if (network == net::ethernet::ETHERTYPE_IPV6) {
        total_length -= net::ip::v6::HEADER_LEN;
        testgen::makeIPv6Header(data, transport, total_length);
        std::span<const uint8_t> span{data, net::ip::v6::HEADER_LEN};
        net::ip::v6::parse(span, ipv6_header, net::Endian::Big);
        data += net::ip::v6::HEADER_LEN;
    } else if (network == net::ethernet::ETHERTYPE_ARP) {
        total_length -= net::arp::MIN_HEADER_LEN + 2 * sizeof(net::ethernet::Header::src_mac) + 2 * sizeof(net::ip::v4::Header::src_ip);
        testgen::makeArpHeader(data);
        data += net::arp::MIN_HEADER_LEN + 2 * sizeof(net::ethernet::Header::src_mac) + 2 * sizeof(net::ip::v4::Header::src_ip);
        return;
    }

    if (transport == net::ip::PROTOCOL_TCP) {
        uint16_t data_offset = randomgen::randRange8(net::tcp::MIN_DATA_OFFSET, net::tcp::MAX_DATA_OFFSET);
        size_t header_length = sizeof(uint32_t) * data_offset;
        total_length -= header_length;
        if (network == net::ethernet::ETHERTYPE_IPV4) {
            testgen::makeTcpHeader(data, ipv4_header, data_offset, total_length);
        } else if (network == net::ethernet::ETHERTYPE_IPV6) {
            testgen::makeTcpHeader(data, ipv6_header, data_offset, total_length);
        }
        data += header_length;
    } else if (transport == net::ip::PROTOCOL_UDP) {
        total_length -= net::udp::HEADER_LEN;
        if (network == net::ethernet::ETHERTYPE_IPV4) {
            testgen::makeUdpHeader(data, ipv4_header, total_length);
        } else if (network == net::ethernet::ETHERTYPE_IPV6) {
            testgen::makeUdpHeader(data, ipv6_header, total_length);
        }
        data += net::udp::HEADER_LEN;
    } else if (transport == net::ip::PROTOCOL_ICMP) {
        total_length -= net::icmp::HEADER_LEN;
        testgen::makeIcmpHeader(data, total_length);
        data += net::icmp::HEADER_LEN;
    } else if (transport == net::ip::PROTOCOL_ICMPV6) {
        total_length -= net::icmpv6::HEADER_LEN;
        testgen::makeIcmpv6Header(data, ipv6_header, total_length);
        data += net::icmpv6::HEADER_LEN;
    }
}

}