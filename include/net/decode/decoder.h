#pragma once

#include <net/capture/packet.h>

#include <span>

namespace net::decode {

ParseError decodePacket(std::span<const uint8_t>& span, Packet& out);
ParseError decodeLayer2(std::span<const uint8_t>& span, Packet& out);
ParseError decodeLayer3(std::span<const uint8_t>& span, Packet& out);
ParseError decodeLayer4(std::span<const uint8_t>& span, Packet& out);

}