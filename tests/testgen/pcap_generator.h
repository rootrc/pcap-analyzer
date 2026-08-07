#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>

namespace testgen {

void makePcapFile(FILE* f, size_t num_packets);

}