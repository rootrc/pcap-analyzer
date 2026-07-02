#include <gtest/gtest.h>
#include <cstdlib>
#include <ctime>
#include <cstring>

#include "common/random_gen.h"

int g_randomizedIterations = 100;

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    unsigned seed = static_cast<unsigned>(std::time(nullptr));

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            seed = std::strtoul(argv[++i], nullptr, 10);
        } else if ((std::strcmp(argv[i], "--n") == 0 || std::strcmp(argv[i], "-n") == 0) && i + 1 < argc) {
            g_randomizedIterations = std::strtoul(argv[++i], nullptr, 10);
        }
    }

    randomgen::init(seed);

    return RUN_ALL_TESTS();
}