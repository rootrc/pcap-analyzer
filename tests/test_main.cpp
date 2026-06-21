#include <gtest/gtest.h>
#include <iostream>

int main(int argc, char** argv) {
    std::cout << "CUSTOM MAIN\n";

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}