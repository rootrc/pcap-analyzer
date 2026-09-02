#include <net/flow/tcp_reassembler.h>

#include <algorithm>
#include <iostream>
#include <assert.h>

namespace net {

constexpr std::string_view toString(TcpState state) noexcept {
    switch (state) {
        case TcpState::Unknown: return "Unknown";
        case TcpState::Closed: return "Closed";
        case TcpState::Listen: return "Listen";
        case TcpState::SynSent: return "SynSent";
        case TcpState::SynReceived: return "SynReceived";
        case TcpState::Established: return "Established";
        case TcpState::FinWait1: return "FinWait1";
        case TcpState::FinWait2: return "FinWait2";
        case TcpState::CloseWait: return "CloseWait";
        case TcpState::Closing: return "Closing";
        case TcpState::LastAck: return "LastAck";
        case TcpState::TimeWait: return "TimeWait";
        default: return "Invalid";
    }
}

std::ostream& operator<<(std::ostream& os, TcpState state) {
    return os << toString(state);
}

void TcpReassembler::onSent(const tcp::Header& header, const std::span<const uint8_t> span) {
    if (header.rst()) {
        state = TcpState::Closed;
        return;
    }
    if (!seeded) {
        if (header.syn()) {
            next_seq = header.seq_number + 1;
            state = header.ack() ? TcpState::SynReceived : TcpState::SynSent;
            seeded = true;
            ingest(header.seq_number + 1, span);
        } else if (header.ack()) {
            next_seq = header.seq_number;
            seeded = true;
            if (state != TcpState::CloseWait) {
                state = TcpState::Established;
            }
            onData(header, span);
        }
        return;
    }
    switch (state) {
        case TcpState::Unknown:
        case TcpState::Closed:
        case TcpState::Listen:
            return;
        case TcpState::SynSent:
            if (header.ack() && !header.syn()) {
                state = TcpState::Established;
            }
            if (state == TcpState::Established) {
                onData(header, span);
            }
            return;
        case TcpState::SynReceived:
            return;
        case TcpState::Established:
        case TcpState::CloseWait:
            onData(header, span);
            return;
        case TcpState::FinWait1:
        case TcpState::FinWait2:
        case TcpState::Closing:
        case TcpState::LastAck:
        case TcpState::TimeWait:
            return;
    }
}

void TcpReassembler::onReceived(const tcp::Header& header) {
    if (header.rst()) {
        state = TcpState::Closed;
        return;
    }
    switch (state) {
        case TcpState::Unknown:
        case TcpState::Closed:
        case TcpState::Listen:
            if (header.syn() && !header.ack()) {
                state = TcpState::Listen;
            } else if (header.ack() && !header.syn()) {
                state = header.fin() ? TcpState::CloseWait : TcpState::Established;
            }
            break;
        case TcpState::SynSent:
            if (header.syn() && !header.ack()) {
                state = TcpState::SynReceived;
            }
            break;
        case TcpState::SynReceived:
            if (header.ack() && !header.syn()) {
                state = header.fin() ? TcpState::CloseWait : TcpState::Established;
            }
            break;
        case TcpState::Established:
            if (header.fin()) {
                state = TcpState::CloseWait;
            }
            break;
        case TcpState::FinWait1:
            if (header.fin() && header.ack() && static_cast<int32_t>(header.ack_number - next_seq) >= 0) {
                state = TcpState::TimeWait;
            } else if (header.fin()) {
                state = TcpState::Closing;
            } else if (header.ack() && static_cast<int32_t>(header.ack_number - next_seq) >= 0) {
                state = TcpState::FinWait2;
            }
            break;
        case TcpState::FinWait2:
            if (header.fin()) {
                state = TcpState::TimeWait;
            }
            break;
        case TcpState::Closing:
            if (header.ack() && static_cast<int32_t>(header.ack_number - next_seq) >= 0) {
                state = TcpState::TimeWait;
            }
            break;
        case TcpState::LastAck:
            if (header.ack() && static_cast<int32_t>(header.ack_number - next_seq) >= 0) {
                state = TcpState::Closed;
            }
            break;
        case TcpState::TimeWait:
        case TcpState::CloseWait:
            break;
    }
}

void TcpReassembler::onData(const tcp::Header& header, const std::span<const uint8_t> span) {
    ingest(header.seq_number, span);
    if (header.fin()) {
        fin_seen = true;
        fin_seq = header.seq_number + static_cast<uint32_t>(span.size());
    }
    if (fin_seen && static_cast<int32_t>(next_seq - fin_seq) >= 0) {
        next_seq++;
        fin_seen = false;
        state = (state == TcpState::CloseWait) ? TcpState::LastAck : TcpState::FinWait1;
    }
}

void TcpReassembler::ingest(uint32_t seq, const std::span<const uint8_t> span) {
    if (!keep_payload) {
        if (seq == next_seq) {
            next_seq += static_cast<uint32_t>(span.size());
        } else if (static_cast<int32_t>(seq - next_seq) < 0) {
            uint32_t overlap = next_seq - seq;
            if (overlap < static_cast<uint32_t>(span.size())) {
                next_seq += static_cast<uint32_t>(span.size()) - overlap;
            }
        }
        return;
    }
    if (assembled.capacity() < INITIAL_CAPACITY) assembled.reserve(INITIAL_CAPACITY);
    if (seq == next_seq) {
        assembled.insert(assembled.end(), span.data(), span.data() + span.size());
        next_seq += static_cast<uint32_t>(span.size());
        drain();
    } else if (static_cast<int32_t>(seq - next_seq) > 0) {
        auto it = std::lower_bound(out_of_order.begin(), out_of_order.end(), seq, [](const Segment& s, uint32_t v) { return s.seq < v; });
        if (it != out_of_order.end() && it->seq == seq) {
            if (span.size() > it->data.size()) {
                if (ooo_bytes + span.size() - it->data.size() <= MAX_OOO_BYTES) {
                    ooo_bytes += span.size() - it->data.size();
                    it->data.assign(span.data(), span.data() + span.size());
                }
             }
        } else if (ooo_bytes + span.size() <= MAX_OOO_BYTES) {
            Segment segment;
            segment.seq = seq;
            segment.data.assign(span.data(), span.data() + span.size());
            out_of_order.insert(it, std::move(segment));
            ooo_bytes += span.size();
         }
    } else {
        uint32_t overlap = next_seq - seq;
        if (overlap < static_cast<uint32_t>(span.size())) {
            assembled.insert(assembled.end(), span.data() + overlap, span.data() + span.size());
            next_seq += static_cast<uint32_t>(span.size()) - overlap;
            drain();
        }
    }
}

void TcpReassembler::drain() {
    size_t len = 0;
    while (len < out_of_order.size() && out_of_order[len].seq == next_seq) {
        const Segment& segment = out_of_order[len];
        assembled.insert(assembled.end(), segment.data.begin(), segment.data.end());
        next_seq += static_cast<uint32_t>(segment.data.size());
        ooo_bytes -= segment.data.size();
        ++len;
    }
    if (len > 0) {
        out_of_order.erase(out_of_order.begin(), out_of_order.begin() + len);
    }
}

size_t TcpReassembler::available() const noexcept {
    return assembled.size() - read_pos;
}

const std::span<const uint8_t> TcpReassembler::peek() const {
    return std::span<const uint8_t>{assembled.data() + read_pos, available()};
}

void TcpReassembler::consume(size_t n) {
    read_pos += std::min(n, available());
    if (read_pos > MIN_COMPACT_BYTES && read_pos > assembled.size() / 2) {
        assembled.erase(assembled.begin(), assembled.begin() + read_pos);
        read_pos = 0;
        if (assembled.capacity() >= SHRINK_THRESHOLD &&
            assembled.capacity() > 4 * assembled.size()) {
            assembled.shrink_to_fit();
        }
    }
}

bool TcpReassembler::hasReadableData() const {
    return state == TcpState::Established || state == TcpState::FinWait1 || state == TcpState::FinWait2;
}

}