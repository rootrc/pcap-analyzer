#pragma once

#include <net/analysis/benchmark.h>
#include <net/capture/capture.h>
#include <net/capture/packet.h>
#include <net/decode/decoder.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <fcntl.h>
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <unistd.h>
#endif

#include <cstdio>
#include <filesystem>
#include <functional>
#include <span>
#include <variant>

namespace net::pcap {

class Reader {
public:
    explicit Reader(const std::filesystem::path& path, size_t print_limit = 0, bool detailed_bench = false, bool verify_checksum = true,
                     uint64_t flow_active_timeout_us = 0, uint64_t flow_idle_timeout_us = FlowTable::DEFAULT_IDLE_TIMEOUT_US);
    Reader(const Reader&) = delete;
    Reader& operator=(const Reader&) = delete;
    ~Reader();

    const Capture& currentCapture() const { return capture_; }
    const FileHeader& fileHeader() const { return file_header_; }
    uint64_t decoded() const { return decoder_.decoded(); }
    const FlowTable& flowTable() const { return decoder_.flowTable(); }
    const AppDecoder& appDecoder() const { return decoder_.appDecoder(); }
    const DnsTable& dnsTable() const { return decoder_.dnsTable(); }
    const StatsEngine& statsEngine() const { return decoder_.statsEngine(); }
    const Benchmark& benchmark() const { return benchmark_; }

    Endian endian() const { return endian_; }
    
    using PacketCallback = std::function<void(const Capture&)>;

    void readAllPackets();
    void readAllPackets(const PacketCallback& on_packet);
    ParseError readPacket();

    uint64_t skipped() const { return skipped_; }
    ParseError lastSkipErr() const { return last_skip_err_; }

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
    Benchmark benchmark_;
    Decoder decoder_;
    bool is_nsec_;
    Endian endian_;
    uint64_t skipped_ = 0;
    ParseError last_skip_err_ = ParseError::None;
    
    static Packet::NetworkHeader networkFromEthertype(uint16_t ethertype) noexcept; 
    static Packet::TransportHeader transportFromProtocol(uint8_t protocal) noexcept;

    ParseError readFileHeader();
};

}
