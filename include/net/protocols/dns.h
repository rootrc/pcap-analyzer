#pragma once

#include <net/util/endian.h>
#include <net/util/parse_error.h>

#include <span>
#include <string>
#include <vector>

// https://datatracker.ietf.org/doc/html/rfc1035

namespace net::dns {

constexpr size_t HEADER_LEN = 12;
constexpr uint16_t PORT = 53;

constexpr size_t QUESTION_HEADER_LEN = 4;
constexpr size_t RESOURCE_HEADER_LEN = 10;

constexpr uint16_t TYPE_A = 1;
constexpr uint16_t TYPE_NS = 2;
constexpr uint16_t TYPE_CNAME = 5;
constexpr uint16_t TYPE_SOA = 6;
constexpr uint16_t TYPE_PTR = 12;
constexpr uint16_t TYPE_MX = 15;
constexpr uint16_t TYPE_TXT = 16;
constexpr uint16_t TYPE_AAAA = 28;
constexpr uint16_t TYPE_SRV = 33;

constexpr uint16_t CLASS_IN = 1;

constexpr uint8_t RCODE_OK = 0;
constexpr uint8_t RCODE_FORMAT = 1;
constexpr uint8_t RCODE_SERVER = 2;
constexpr uint8_t RCODE_NAME = 3;
constexpr uint8_t RCODE_NOTIMP = 4;
constexpr uint8_t RCODE_REFUSED = 5;

constexpr int MaxDnsCompressionJumps = 10;
constexpr uint8_t DnsCompressionPointerMask = 0xC0;
// RFC 1035 2.3.4: a domain name (label octets + length octets) is capped at 255 octets.
constexpr size_t MaxDnsNameOctets = 255;

#pragma pack(push, 1)
struct WireHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
struct WireQuestion {
    uint16_t qtype;
    uint16_t qclass;
};
struct WireResourceHeader {
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rdlength;
};
#pragma pack(pop)
static_assert(sizeof(WireHeader) == HEADER_LEN);
static_assert(sizeof(WireQuestion) == QUESTION_HEADER_LEN);
static_assert(sizeof(WireResourceHeader) == RESOURCE_HEADER_LEN);

struct Question {
    std::string name;
    uint16_t qtype;
    uint16_t qclass;
};

struct ResourceRecord {
    std::string name;
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    std::vector<uint8_t> rdata;
};

struct Header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
    std::vector<Question> questions;
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authority;
    std::vector<ResourceRecord> additional;

    bool isResponse() const noexcept { return flags & 0x8000; }
    uint8_t opcode() const noexcept { return (flags & 0x7800) >> 11; }
    bool isAA() const noexcept { return flags & 0x0400; }
    bool isTC() const noexcept { return flags & 0x0200; }
    bool isRD() const noexcept { return flags & 0x0100; }
    bool isRA() const noexcept { return flags & 0x0080; }
    uint8_t rcode() const noexcept { return flags & 0x000F; }

    std::string toString() const noexcept;
    std::string toJson() const noexcept;
};

ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian);

const char* typeName(uint16_t t);
std::ostream& operator<<(std::ostream& os, const Header& h);

}