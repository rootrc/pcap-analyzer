#pragma once

#include <cstdio>
#include <vector>

#include <net/capture/packet.h>
#include <net/core/buffer_view.h>

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

    private:
        FILE* f_;
        FileHeader file_header_{};
        Endian endian_;
        uint8_t buffer_[FILE_HEADER_LEN];
        
        static Packet::TransportType transportFromProtocol(uint8_t protocal);

        ParseError readFileHeader();
        ParseError decodePacket(BufferView& buf, Packet& out);
        ParseError decodeLayer3(BufferView& buf, Packet& out);
        ParseError decodeLayer4(BufferView& buf, Packet& out);
    };
}
