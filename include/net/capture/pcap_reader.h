#pragma once

#include <net/capture/packet.h>
#include <net/capture/decoder.h>

#include <cstdio>

#include <variant>
#include <span>

namespace net::pcap {

class Reader {
public:
    struct Capture {
        pcap::PacketHeader packetHeader;
        Packet pkt;
    };
    explicit Reader(FILE* f) : f_(f) {
        if (!f_) throw std::invalid_argument("pcap::Reader: null FILE*");
        readFileHeader();
    }

    Reader(const Reader&) = delete;
    Reader& operator=(const Reader&) = delete;

    const FileHeader& fileHeader() const { return file_header_; }
    Endian endian() const { return endian_; }
    
    ParseError next(Capture& out);

    uint64_t skipped() const { return skipped_; }
    ParseError lastSkipErr() const { return last_skip_err_; }

    void printNetwork(std::ostream& os, const Capture& out) const;
    void printTransport(std::ostream& os, const Capture& out) const;
    
private:
    FILE* f_;
    FileHeader file_header_{};
    Endian endian_;
    uint8_t buffer_[FILE_HEADER_LEN];
    uint64_t skipped_ = 0;
    ParseError last_skip_err_ = ParseError::None;
    
    static Packet::NetworkHeader networkFromEthertype(uint16_t ethertype) noexcept; 
    static Packet::TransportHeader transportFromProtocol(uint8_t protocal) noexcept;

    ParseError readFileHeader();
};

}
