#pragma once

#include <net/core/endian.h>
#include <net/core/parse_error.h>

#include <ostream>
#include <span>

// https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html

namespace net::pcap {

constexpr size_t FILE_HEADER_LEN = 24;
constexpr size_t PACKET_HEADER_LEN = 16;

constexpr uint32_t PCAP_MAGIC_USEC_BE = 0xd4c3b2a1;
constexpr uint32_t PCAP_MAGIC_USEC_LE = 0xa1b2c3d4;
constexpr uint32_t PCAP_MAGIC_NSEC_BE = 0x4d3cb2a1;
constexpr uint32_t PCAP_MAGIC_NSEC_LE = 0xa1b23c4d;

constexpr uint32_t LINKTYPE_ETHERNET = 1;

#pragma pack(push, 1)
struct FileHeader {
    uint32_t magic_number;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t snaplen;
    uint32_t linktype;
};
struct PacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};
#pragma pack(pop)
static_assert(sizeof(FileHeader) == FILE_HEADER_LEN);
static_assert(sizeof(PacketHeader) == PACKET_HEADER_LEN);

ParseError parse(std::span<const uint8_t>& span, FileHeader& header, net::Endian& endian);
ParseError parse(std::span<const uint8_t>& span, PacketHeader& header, net::Endian endian);

std::ostream& operator<<(std::ostream& os, const FileHeader& h);
std::ostream& operator<<(std::ostream& os, const PacketHeader& h);

}