#pragma once

#include <net/capture/packet.h>
#include <net/core/buffer_view.h>

#include <cstdio>
#include <vector>
#include <variant>

template<typename... Ts>
struct overload : Ts... { using Ts::operator()...; };

template<typename... Ts>
overload(Ts...) -> overload<Ts...>;

namespace net::pcap {
    class Reader {
    public:
        explicit Reader(FILE* f) : f_(f) {
            if (!f_) throw std::invalid_argument("pcap::Reader: null FILE*");
            readFileHeader();
        }

        Reader(const Reader&) = delete;
        Reader& operator=(const Reader&) = delete;

        const FileHeader& fileHeader() const { return file_header_; }
        Endian endian() const { return endian_; }
        
        ParseError next(Packet& out);

        void printNetwork(std::ostream& os, const Packet& out) const;
        void printTransport(std::ostream& os, const Packet& out) const;
    private:
        FILE* f_;
        FileHeader file_header_{};
        Endian endian_;
        uint8_t buffer_[FILE_HEADER_LEN];
        
        static Packet::NetworkHeader networkFromEthertype(uint16_t ethertype) noexcept; 
        static Packet::TransportHeader transportFromProtocol(uint8_t protocal) noexcept;

        ParseError readFileHeader();
        ParseError decodePacket(BufferView& buf, Packet& out);
        ParseError decodeLayer2(BufferView& buf, Packet& out);
        ParseError decodeLayer3(BufferView& buf, Packet& out);
        ParseError decodeLayer4(BufferView& buf, Packet& out);
    };
}
