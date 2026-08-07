
#include <gtest/gtest.h>
#include <net/capture/pcap_reader.h>
#include "../common/header_tester.h"
#include "../testgen/pcap_generator.h"
#include "../testgen/packet_generator.h"

#include <cstdio>
#include <filesystem>

net::ParseError parsePcapFile(std::span<const uint8_t>&) {
    net::pcap::Reader reader("pcap_reader_test.pcap");
    reader.readAllPackets();
    return reader.lastSkipErr();
}

void makePcapFile() {
    FILE* file = std::fopen("pcap_reader_test.pcap", "wb");
    if (!file) {
        throw std::runtime_error("pcap_reader_tests: failed to open temp file");
    }
    testgen::makePcapFile(file, g_randomizedIterations);
    std::fclose(file);
}

RANDOMIZED_TEST(PCAP_READER, Randomized, 10, [](uint8_t*) {makePcapFile();}, parsePcapFile)