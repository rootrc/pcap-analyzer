#include <net/analysis/benchmark.h>
#include <net/util/text.h>

#include <iomanip>
#include <sstream>

namespace net {

std::string_view Benchmark::toString(Phase phase) noexcept {
    switch (phase) {
        case Phase::Total: return "total";
        case Phase::FileHeader: return "file header";
        case Phase::PacketHeader: return "packet header";
        case Phase::Decode: return "decode";
        case Phase::DecodePacket: return "decode packet";
        case Phase::FlowLookup: return "flow lookup";
        case Phase::AppDecode: return "app decode";
        case Phase::Count: break;
    }
    return "unknown";
}

std::string Benchmark::formatDuration(uint64_t ns) noexcept {
    std::ostringstream oss;
    util::printDuration(oss, ns);
    return oss.str();
}

void Benchmark::start(Phase phase) noexcept {
    PhaseState& state = phases_[static_cast<size_t>(phase)];
    state.started = std::chrono::steady_clock::now();
    state.running = true;
}

void Benchmark::stop(Phase phase) noexcept {
    auto now = std::chrono::steady_clock::now();
    PhaseState& state = phases_[static_cast<size_t>(phase)];
    if (!state.running) return;
    state.running = false;
    state.stats.elapsed_ns += static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now - state.started).count());
    ++state.stats.calls;
}

std::string Benchmark::toString() const noexcept {
    constexpr int VALUE_COLUMN = 20;

    std::ostringstream oss;
    auto flags = oss.flags();
    oss << "benchmark {\n";
    oss << "  " << std::left << std::setw(VALUE_COLUMN - 2) << "total";
    util::printDuration(oss, elapsedNs(Phase::Total));
    oss << '\n';

    auto printPhase = [&](Phase phase, int indent) {
        const PhaseStats& stats = this->phase(phase);
        oss << std::string(indent, ' ') << std::left << std::setw(VALUE_COLUMN - indent) << toString(phase);
        util::printDuration(oss, stats.elapsed_ns);
        oss << "  (" << stats.calls << (stats.calls == 1 ? " call" : " calls");
        if (stats.calls) {
            oss << ", ";
            util::printDuration(oss, stats.elapsed_ns / stats.calls);
            oss << " avg";
        }
        oss << ")\n";
    };

    for (Phase phase : {Phase::FileHeader, Phase::PacketHeader}) {
        printPhase(phase, 4);
    }
    printPhase(Phase::Decode, 4);
    for (Phase phase : {Phase::DecodePacket, Phase::FlowLookup, Phase::AppDecode}) {
        printPhase(phase, 6);
    }

    double seconds = static_cast<double>(elapsedNs(Phase::Total)) / 1e9;
    oss << "  " << std::left << std::setw(VALUE_COLUMN - 2) << "throughput";
    util::printBytes(oss, bytes_);
    oss << " in ";
    util::printDuration(oss, elapsedNs(Phase::Total));
    oss << "  (";
    util::printRate(oss, seconds > 0.0 ? (static_cast<double>(bytes_) * 8.0 / seconds) : 0.0);
    oss << ", " << (seconds > 0.0 ? static_cast<uint64_t>(static_cast<double>(packets()) / seconds) : 0) << " pkt/s)\n";

    oss << "}";
    oss.flags(flags);
    return oss.str();
}

std::string Benchmark::toJson() const noexcept {
    std::ostringstream oss;
    oss << "\"benchmark\": {\n"
        << "  \"bytes\": " << bytes_ << ",\n"
        << "  \"phases\": [\n";
    for (size_t i = 0; i < PHASE_COUNT; ++i) {
        Phase phase = static_cast<Phase>(i);
        if (phase == Phase::Count) continue;
        const PhaseStats& stats = this->phase(phase);
        if (i) oss << ",\n";
        oss << "    {\n"
            << "      \"phase\": \"" << toString(phase) << "\",\n"
            << "      \"calls\": " << stats.calls << ",\n"
            << "      \"elapsed_ns\": " << stats.elapsed_ns << '\n'
            << "    }";
    }
    oss << "\n  ]\n"
        << "}";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const Benchmark& benchmark) {
    return os << benchmark.toString();
}

}
