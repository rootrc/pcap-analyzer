#include "protocol_generator.h"

#include <cstring>

namespace testgen {

uint16_t checksum(const uint8_t* data, size_t len, uint64_t initial_sum) {
    uint64_t sum = initial_sum;
    
    for (size_t i = 0; i < len; i += 2) {
        if (i + 1 < len) {
            sum += (data[i] << 8) | data[i + 1];
        } else {
            sum += (data[i] << 8);
        }
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

void makeEthernetHeader(uint8_t* data, uint16_t ethertype) {
    net::ethernet::Header h{};
    for (int i = 0; i < 6; ++i) {
        h.dst_mac[i] = randomgen::rand8();
        h.src_mac[i] = randomgen::rand8();
    }
    h.ethertype = net::bswap16(ethertype);
    memcpy(data, &h, net::ethernet::HEADER_LEN);
}

void makeIPv4Header(uint8_t* data, uint8_t protocol, uint8_t ihl, uint16_t payload_len) {
    net::ip::v4::Header h{};

    if (ihl < net::ip::v4::MIN_HEADER_LEN / 4 || ihl > net::ip::v4::MAX_HEADER_LEN / 4) {
        throw std::out_of_range("ihl out of range [5, 15]");
    }
    uint8_t version = 4;
    size_t header_len = 4 * ihl;

    h.version_ihl = (version << 4) | ihl;
    h.tos = 0;
    h.total_length = net::bswap16(header_len + payload_len);
    h.identification = randomgen::rand16();
    h.flags_fragment = net::bswap16(0x4000);
    h.ttl = randomgen::randRange8(32, 128);
    h.protocol = protocol;
    h.checksum = 0;
    h.src_ip = randomgen::rand32();
    h.dst_ip = randomgen::rand32();
    for (size_t i = net::ip::v4::MIN_HEADER_LEN; i < header_len; ++i) {
        data[i] = randomgen::rand8();
    }

    memcpy(data, &h, net::ip::v4::MIN_HEADER_LEN);
    h.checksum = checksum(data, header_len);
    data[10] = h.checksum >> 8;
    data[11] = h.checksum & 0xFF;
}

void makeIPv6Header(uint8_t* data, uint8_t next_header, uint16_t payload_length) {
    net::ip::v6::Header h{};

    uint32_t tc = randomgen::rand8();
    uint32_t flow = randomgen::rand32() & 0xFFFFF;
    h.version_tc_fl = net::bswap32((6u << 28) | (tc << 20) | flow);
    h.payload_length = net::bswap16(payload_length);
    h.next_header = next_header;
    h.hop_limit = randomgen::randRange8(32, 128);
    for (int i = 0; i < 16; ++i) {
        h.src_ip[i] = randomgen::rand8();
        h.dst_ip[i] = randomgen::rand8();
    }
    memcpy(data, &h, net::ip::v6::HEADER_LEN);
}

void makeTcpHeader(uint8_t* data, uint64_t pseudo_sum, uint8_t data_offset, size_t payload_len) {
    net::tcp::Header h{};

    if (data_offset < net::tcp::MIN_HEADER_LEN / 4 || data_offset > 15) {
        throw std::out_of_range("data_offset out of range [5, 15]");
    }
    size_t header_len = 4 * data_offset;

    h.src_port = randomgen::rand16();
    h.dst_port = randomgen::rand16();
    h.seq_number = randomgen::rand32();
    h.ack_number = randomgen::rand32();
    h.data_offset_reserved = data_offset << 4;
    h.flags = 0x18;
    h.window_size = net::bswap16(randomgen::randRange16(1024, 65535));
    h.checksum = 0;
    h.urgent_pointer = 0;
    for (size_t i = net::tcp::MIN_HEADER_LEN; i < header_len + payload_len; ++i) {
        data[i] = randomgen::rand8();
    }

    memcpy(data, &h, net::tcp::MIN_HEADER_LEN);
    h.checksum = checksum(data, header_len + payload_len, pseudo_sum);
    data[16] = h.checksum >> 8;
    data[17] = h.checksum & 0xFF;
}

void makeTcpHeader(uint8_t* data, const net::ip::v4::Header& ip, uint8_t data_offset, size_t payload_len) {
    makeTcpHeader(data, net::ip::v4::computePseudoHeaderSum(ip), data_offset, payload_len);
}

void makeTcpHeader(uint8_t* data, const net::ip::v6::Header& ip, uint8_t data_offset, size_t payload_len) {
    makeTcpHeader(data, net::ip::v6::computePseudoHeaderSum(ip), data_offset, payload_len);
}

void makeUdpHeader(uint8_t* data, uint64_t pseudo_sum, uint16_t udp_length) {
    net::udp::Header h{};

    h.src_port = randomgen::rand16();
    h.dst_port = randomgen::rand16();
    h.length = net::bswap16(udp_length);
    h.checksum = 0;

    memcpy(data, &h, net::udp::HEADER_LEN);
    h.checksum = checksum(data, udp_length, pseudo_sum);
    data[6] = h.checksum >> 8;
    data[7] = h.checksum & 0xFF;
}

void makeUdpHeader(uint8_t* data, const net::ip::v4::Header& ip, uint16_t payload_length) {
    makeUdpHeader(data, net::ip::v4::computePseudoHeaderSum(ip), net::udp::HEADER_LEN + payload_length);
}

void makeUdpHeader(uint8_t* data, const net::ip::v6::Header& ip, uint16_t payload_length) {
    makeUdpHeader(data, net::ip::v6::computePseudoHeaderSum(ip), net::udp::HEADER_LEN + payload_length);
}

}