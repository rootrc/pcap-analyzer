#pragma once

#include <net/decode/packet.h>
#include <net/capture/pcap.h>

namespace net::pcap {

struct Capture {
    uint64_t ts_us;
    pcap::PacketHeader packetHeader;
    Packet pkt;
};

}