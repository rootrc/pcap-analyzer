#pragma once

#include <net/util/endian.h>
#include <net/util/parse_error.h>

#include <span>

// https://datatracker.ietf.org/doc/html/rfc792

namespace net::icmp {

constexpr size_t HEADER_LEN = 8;

constexpr uint8_t TYPE_ECHO_REPLY = 0;
constexpr uint8_t TYPE_UNREACHABLE = 3;
constexpr uint8_t TYPE_SOURCE_QUENCH = 4;
constexpr uint8_t TYPE_REDIRECT = 5;
constexpr uint8_t TYPE_ECHO_REQUEST = 8;
constexpr uint8_t TYPE_TTL_EXCEEDED = 11;
constexpr uint8_t TYPE_PARAM_PROBLEM = 12;
constexpr uint8_t TYPE_TIMESTAMP = 13;
constexpr uint8_t TYPE_TIMESTAMP_REPLY = 14;
constexpr uint8_t TYPE_INFO_REQUEST = 15;
constexpr uint8_t TYPE_INFO_REPLY = 16;

constexpr uint8_t CODE_NET_UNREACHABLE = 0;
constexpr uint8_t CODE_HOST_UNREACHABLE = 1;
constexpr uint8_t CODE_PORT_UNREACHABLE = 3;

constexpr uint8_t CODE_TTL_IN_TRANSIT = 0;
constexpr uint8_t CODE_TTL_REASSEMBLY = 1;

constexpr uint8_t CODE_PARAM_BAD_HEADER = 0;
constexpr uint8_t CODE_PARAM_MISSING_OPT = 1;

constexpr uint8_t CODE_REDIRECT_NET = 0;
constexpr uint8_t CODE_REDIRECT_HOST = 1;
constexpr uint8_t CODE_REDIRECT_TOS_NET = 2;
constexpr uint8_t CODE_REDIRECT_TOS_HOST = 3;

#pragma pack(push, 1)
struct Header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    union {
        struct { uint8_t pointer; uint8_t pad[3]; } param_problem; // type 12
        uint32_t gateway; // type 5
        struct { uint16_t id; uint16_t seq; } echo; // type 0/8
    }; // 13/14/15/16 unsupported
};
#pragma pack(pop)
static_assert(sizeof(Header) == HEADER_LEN);

ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian);

std::ostream& operator<<(std::ostream& os, const Header& h);

}