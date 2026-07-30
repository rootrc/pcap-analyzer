#pragma once

#include <net/util/endian.h>
#include "protocol_generator.h"

namespace testgen {

void makePcapFileHeader(uint8_t* data, net::Endian endian = net::Endian::Little);
void makePcapPacketHeader(uint8_t* data, uint32_t captured_len, net::Endian endian = net::Endian::Little);
void makePcapPacket(uint8_t* data, size_t total_length);

}