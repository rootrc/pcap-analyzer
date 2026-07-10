#pragma once

#include <net/capture/packet.h>
#include <net/capture/decoder.h>
#include <net/analysis/flow_tracker.h>

#include <cstdio>

#include <variant>
#include <span>

namespace net::pcap {

class Reader {
public:
    struct Capture {
        uint64_t ts_us;
        pcap::PacketHeader packetHeader;
        Packet pkt;
    };
    explicit Reader(FILE* f) : f_(f) {
        if (!f_) throw std::invalid_argument("pcap::Reader: null FILE*");
        readFileHeader();
    }

    Reader(const Reader&) = delete;
    Reader& operator=(const Reader&) = delete;

    const Capture& currentCapture() const { return capture_; }
    const FileHeader& fileHeader() const { return file_header_; }
    const FlowTable& flowTable() const { return flowTable_; }
    Endian endian() const { return endian_; }
    
    void readAllPackets();
    ParseError readPacket();

    uint64_t skipped() const { return skipped_; }
    ParseError lastSkipErr() const { return last_skip_err_; }

    void print(std::ostream& os, const Capture& out) const;
    
private:
    FILE* f_;
    Capture capture_{};
    FileHeader file_header_{};
    FlowTable flowTable_{};
    bool is_nsec_;
    Endian endian_;
    uint8_t buffer_[FILE_HEADER_LEN];
    uint64_t skipped_ = 0;
    ParseError last_skip_err_ = ParseError::None;
    
    static Packet::NetworkHeader networkFromEthertype(uint16_t ethertype) noexcept; 
    static Packet::TransportHeader transportFromProtocol(uint8_t protocal) noexcept;

    ParseError readFileHeader();
};

}
