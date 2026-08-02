#pragma once

#include <net/capture/capture.h>
#include <net/capture/packet.h>
#include <net/decode/decoder.h>

#include <cstdio>

#include <variant>
#include <span>

#include <filesystem>

namespace net::pcap {

class Reader {
public:
    explicit Reader(const std::filesystem::path& path);
    Reader(const Reader&) = delete;
    Reader& operator=(const Reader&) = delete;
    ~Reader();

    const Capture& currentCapture() const { return capture_; }
    const FileHeader& fileHeader() const { return file_header_; }
    const FlowTable& flowTable() const { return decoder_.flowTable(); }
    const AppDecoder& appDecoder() const { return decoder_.appDecoder(); }
    const DnsTable& dnsTable() const { return decoder_.dnsTable(); }
    Endian endian() const { return endian_; }
    
    void readAllPackets();
    ParseError readPacket();

    uint64_t skipped() const { return skipped_; }
    ParseError lastSkipErr() const { return last_skip_err_; }

    void print(std::ostream& os, const Capture& out) const;
    
private:
#ifdef _WIN32
    HANDLE file_ = INVALID_HANDLE_VALUE;
    HANDLE mapping_ = nullptr;
#else
    int fd_ = -1;
#endif
    std::span<const uint8_t> span_;
    Capture capture_{};
    FileHeader file_header_{};
    Decoder decoder_{};
    bool is_nsec_;
    Endian endian_;
    uint64_t skipped_ = 0;
    ParseError last_skip_err_ = ParseError::None;
    
    static Packet::NetworkHeader networkFromEthertype(uint16_t ethertype) noexcept; 
    static Packet::TransportHeader transportFromProtocol(uint8_t protocal) noexcept;

    ParseError readFileHeader();
};

}
