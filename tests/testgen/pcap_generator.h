#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>

namespace testgen {

constexpr size_t PACKET_LEN = 1024;

void makePcapFile(FILE* f, size_t num_packets);

}