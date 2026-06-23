#include <cstdint>
#include <cstdlib>
#include <ctime>

namespace randomgen {
    inline uint8_t rand8()  { return static_cast<uint8_t>(std::rand() & 0xFF); }
    inline uint16_t rand16() { return static_cast<uint16_t>(std::rand() & 0xFFFF); }
    inline uint32_t rand32() { return (static_cast<uint32_t>(std::rand()) << 16) | (std::rand() & 0xFFFF); }
    inline uint16_t randRange16(uint16_t lo, uint16_t hi) { return lo + (std::rand() % (hi - lo + 1)); }
    inline uint8_t randRange8 (uint8_t lo, uint8_t  hi) { return lo + (std::rand() % (hi - lo + 1)); }
    inline void init(unsigned seed = static_cast<unsigned>(std::time(nullptr))) { std::srand(seed); }
}