#pragma once

#include "packet.h"

#include <span>

template<typename... Ts>
struct overload : Ts... { using Ts::operator()...; };

template<typename... Ts>
overload(Ts...) -> overload<Ts...>;

namespace net::decode {

ParseError decodePacket(std::span<const uint8_t>& span, Packet& out);
ParseError decodeLayer2(std::span<const uint8_t>& span, Packet& out);
ParseError decodeLayer3(std::span<const uint8_t>& span, Packet& out);
ParseError decodeLayer4(std::span<const uint8_t>& span, Packet& out);

}