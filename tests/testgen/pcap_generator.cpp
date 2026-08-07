#include "pcap_generator.h"
#include "packet_generator.h"
#include <net/capture/pcap.h>

#include <stdexcept>

namespace testgen {

void makePcapFile(FILE* f, size_t N) {
    if (!f) throw std::invalid_argument("makePcapFile: null FILE*");

    uint8_t data[PACKET_LEN];
    makePcapFileHeader(data);
    if (fwrite(data, 1, net::pcap::FILE_HEADER_LEN, f) != net::pcap::FILE_HEADER_LEN) {
        throw std::runtime_error("makePcapFile: failed to write file header");
    }

    for (size_t i = 0; i < N; ++i) {
        makePcapPacket(data, PACKET_LEN);
        if (fwrite(data, 1, PACKET_LEN, f) != PACKET_LEN) {
            throw std::runtime_error("makePcapFile: failed to write packet");
        }
    }
}

}