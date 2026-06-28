#pragma once

#include <net/protocols/protocols.h>
#include "../common/random_gen.h"

namespace testgen {

uint16_t checksum(const uint8_t* data, size_t len, uint64_t initial_sum = 0);
void makeEthernetHeader(uint8_t* data, uint16_t ethertype);
void makeVlanHeader(uint8_t* data, uint16_t ethertype);
void makeIPv4Header(uint8_t* data, uint8_t protocol, uint8_t ihl, uint16_t payload_len = 0);
void makeIPv6Header(uint8_t* data, uint8_t next_header, uint16_t payload_length = 0);
void makeArpHeader(uint8_t* data);
void makeTcpHeader(uint8_t* data, uint64_t pseudo_sum, uint8_t data_offset, size_t payload_len);
void makeTcpHeader(uint8_t* data, const net::ip::v4::Header& ip, uint8_t data_offset, size_t payload_len = 0);
void makeTcpHeader(uint8_t* data, const net::ip::v6::Header& ip, uint8_t data_offset, size_t payload_len = 0);
void makeUdpHeader(uint8_t* data, uint64_t pseudo_sum, uint16_t udp_length);
void makeUdpHeader(uint8_t* data, const net::ip::v4::Header& ip, uint16_t payload_length = 0);
void makeUdpHeader(uint8_t* data, const net::ip::v6::Header& ip, uint16_t payload_length = 0);

}