#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>
#include <string_view>

namespace net {

class Benchmark {
public:
    enum class Phase : uint8_t {
        Total,
        FileHeader,
        PacketHeader,
        Decode,
        DecodePacket,
        FlowLookup,
        AppDecode,
        Count
    };
    static constexpr size_t PHASE_COUNT = static_cast<size_t>(Phase::Count);
    static std::string_view toString(Phase phase) noexcept;
    static std::string formatDuration(uint64_t ns) noexcept;

    struct PhaseStats {
        uint64_t calls = 0;
        uint64_t elapsed_ns = 0;    };

    void start(Phase phase) noexcept;
    void stop(Phase phase) noexcept;

    const PhaseStats& phase(Phase phase) const noexcept { return phases_[static_cast<size_t>(phase)].stats; }
    uint64_t elapsedNs(Phase phase) const noexcept { return phases_[static_cast<size_t>(phase)].stats.elapsed_ns; }
    uint64_t calls(Phase phase) const noexcept { return phases_[static_cast<size_t>(phase)].stats.calls; }

    void setBytes(uint64_t bytes) noexcept { bytes_ = bytes; }
    uint64_t packets() const noexcept { return calls(Phase::PacketHeader); }

    std::string toString() const noexcept;
    std::string toJson() const noexcept;

private:
    struct PhaseState {
        PhaseStats stats;
        std::chrono::steady_clock::time_point started{};
        bool running = false;
    };

    PhaseState phases_[PHASE_COUNT]{};
    uint64_t bytes_ = 0;
};

inline std::ostream& operator<<(std::ostream& os, Benchmark::Phase phase) { return os << Benchmark::toString(phase); }
std::ostream& operator<<(std::ostream& os, const Benchmark& benchmark);

}
