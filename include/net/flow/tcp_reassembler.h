#include <net/protocols/tcp.h>

#include <map>
#include <vector>

namespace net {

struct TcpReassembler {
    static constexpr size_t MAX_OOO_BYTES = 1 << 20;
    static constexpr size_t MIN_COMPACT_BYTES = 4096;

    uint32_t next_seq = 0;
    bool started = false;
    bool closed = false;

    bool fin_seen = false;
    uint32_t fin_seq = 0;

    size_t ooo_bytes = 0;
    size_t assembled_offset = 0;

    std::map<uint32_t, std::vector<uint8_t>> out_of_order;
    std::vector<uint8_t> assembled;

    void push(const tcp::Header& tcp, const std::span<const uint8_t>& span);
    void queue_out_of_order(uint32_t seq, std::span<const uint8_t> span);
    size_t available() const;
    const std::span<const uint8_t> peek(size_t n) const;
    void consume(size_t n);
private:
    size_t read_pos = 0;
    void drain();
};

}