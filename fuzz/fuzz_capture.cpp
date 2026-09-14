#include <net/capture/pcap_reader.h>

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <streambuf>
#include <vector>

namespace {

struct NullBuf : std::streambuf {
    int overflow(int c) override { return c; }
};

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::vector<uint8_t> buf(data, data + size);

    net::Decoder::Config config{};
    config.verify_checksum = false;
    net::pcap::Reader reader{std::span<const uint8_t>{buf}, config};

    NullBuf null_buf;
    std::ostream null_os{&null_buf};
    reader.readAllPackets([&](const net::pcap::Capture& capture) { reader.print(null_os, capture); });

    const net::StatsEngine& stats = reader.statsEngine();
    (void)stats.toString();
    (void)stats.toJson();
    stats.printDns(null_os);
    stats.printHttp(null_os);
    return 0;
}
