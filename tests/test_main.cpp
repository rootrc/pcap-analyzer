#include <gtest/gtest.h>
#include "common/random_gen.h"

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    unsigned seed = static_cast<unsigned>(std::time(nullptr));

    if (argc > 1) {
        seed = std::strtoul(argv[1], nullptr, 10);
    }

    randomgen::init(seed);

    return RUN_ALL_TESTS();
}