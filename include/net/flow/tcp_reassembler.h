#include <net/protocols/tcp.h>

#include <vector>
#include <string>

namespace net {

enum class TcpState {
    Unknown,
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait
};

constexpr std::string_view toString(TcpState state) noexcept;

std::ostream& operator<<(std::ostream& os, TcpState state);

struct TcpReassembler {
    static constexpr size_t MAX_OOO_BYTES = 1 << 20;
    static constexpr size_t MIN_COMPACT_BYTES = 4096;
    static constexpr size_t INITIAL_CAPACITY = 4096;
    static constexpr size_t SHRINK_THRESHOLD = 64 * 1024;

    TcpState state = TcpState::Unknown;
    uint32_t next_seq = 0;
    size_t ooo_bytes = 0;

    struct Segment {
        uint32_t seq = 0;
        std::vector<uint8_t> data;
    };
    std::vector<Segment> out_of_order;
    std::vector<uint8_t> assembled;

    bool fin_seen = false;
    uint32_t fin_seq = 0;

    bool seeded = false;

    bool keep_payload = true;

    void onSent(const tcp::Header& header, const std::span<const uint8_t> span);
    void onReceived(const tcp::Header& header);

    size_t available() const noexcept;
    const std::span<const uint8_t> peek() const;
    void consume(size_t n);

    bool hasReadableData() const;
private:
    size_t read_pos = 0;
    void ingest(uint32_t seq, const std::span<const uint8_t> span);
    void onData(const tcp::Header& header, const std::span<const uint8_t> span);
    void drain();
};

}