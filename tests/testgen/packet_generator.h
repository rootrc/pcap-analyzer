#pragma once

#include <net/util/endian.h>
#include "protocol_generator.h"

namespace testgen {

constexpr size_t PACKET_LEN = 1 << 10;

void makePcapFileHeader(uint8_t* data, net::Endian endian = net::Endian::Little);
void makePcapPacketHeader(uint8_t* data, uint32_t captured_len = PACKET_LEN, net::Endian endian = net::Endian::Little);
void makePcapPacket(uint8_t* data, size_t total_length = PACKET_LEN);

}