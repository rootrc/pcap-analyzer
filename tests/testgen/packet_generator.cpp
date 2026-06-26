#include "packet_generator.h"

#include <cstring>

namespace testgen {

void makePcapFileHeader(uint8_t* data, net::Endian endian) {
    net::pcap::FileHeader h{};

    h.magic_number = (endian == net::Endian::Little) ? net::pcap::PCAP_MAGIC_USEC_LE : net::pcap::PCAP_MAGIC_USEC_BE;
    h.major_version = net::toHost16(2, endian);
    h.minor_version = net::toHost16(4, endian);
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

inline uint16_t getRandomNetwork() {
    int random = std::rand();
    if (random % 2 == 0) {
        return net::ethernet::ETHERTYPE_IPV4;
    } else if (random % 2 == 1) {
        return net::ethernet::ETHERTYPE_IPV6;
    }
    return 0;
}

inline uint8_t getRandomTransport() {
    int random = std::rand();
    if (random % 2 == 0) {
        return net::ip::PROTOCOL_UDP;
    } else if (random % 2 == 1) {
        return net::ip::PROTOCOL_TCP;
    }
    return 0;
}

void makePcapPacket(uint8_t* data, size_t total_length) {
    uint16_t network = getRandomNetwork();
    uint8_t transport = getRandomTransport();
    uint16_t ihl = randomgen::randRange8(net::ip::v4::MIN_HEADER_LEN / 4, net::ip::v4::MAX_HEADER_LEN / 4);
    uint16_t data_offset = randomgen::randRange8(net::tcp::MIN_HEADER_LEN / 4, net::tcp::MAX_HEADER_LEN / 4);
    
    total_length -= net::pcap::PACKET_HEADER_LEN;
    testgen::makePcapPacketHeader(data, total_length, net::Endian::Little);
    data += net::pcap::PACKET_HEADER_LEN;
    
    total_length -= net::ethernet::HEADER_LEN;
    testgen::makeEthernetHeader(data, network);
    data += net::ethernet::HEADER_LEN;
    
    net::ip::v4::Header ipv4_header{};
    net::ip::v6::Header ipv6_header{};
    if (network == net::ethernet::ETHERTYPE_IPV4) {
        total_length -= 4 * ihl;
        testgen::makeIPv4Header(data, transport, ihl, total_length);
        std::span<const uint8_t> span{data, static_cast<size_t>(4 * ihl)};
        net::ip::v4::parse(span, ipv4_header, net::Endian::Big);
        data += 4 * ihl;
    } else if (network == net::ethernet::ETHERTYPE_IPV6) {
        total_length -= net::ip::v6::HEADER_LEN;
        testgen::makeIPv6Header(data, transport, total_length);
        std::span<const uint8_t> span{data, net::ip::v6::HEADER_LEN};
        net::ip::v6::parse(span, ipv6_header, net::Endian::Big);
        data += net::ip::v6::HEADER_LEN;
    }

    if (transport == net::ip::PROTOCOL_TCP) {
        total_length -= 4 * data_offset;
        if (network == net::ethernet::ETHERTYPE_IPV4) {
            testgen::makeTcpHeader(data, ipv4_header, data_offset, total_length);
        } else if (network == net::ethernet::ETHERTYPE_IPV6) {
            testgen::makeTcpHeader(data, ipv6_header, data_offset, total_length);
        }
        data += 4 * data_offset;
    } else if (transport == net::ip::PROTOCOL_UDP) {
        total_length -= net::udp::HEADER_LEN;
        if (network == net::ethernet::ETHERTYPE_IPV4) {
            testgen::makeUdpHeader(data, ipv4_header, total_length);
        } else if (network == net::ethernet::ETHERTYPE_IPV6) {
            testgen::makeUdpHeader(data, ipv6_header, total_length);
        }
        data += net::udp::HEADER_LEN;
    }
}

}