#include <net/flow/tcp_reassembler.h>
#include <iostream>
#include <assert.h>

namespace net {

void TcpReassembler::push( const tcp::Header& tcp, const std::span<const uint8_t>& span) {
    if (closed) {
        return;
    }
    if (tcp.rst()) {
        closed = true;
        return;
    }
    if (tcp.syn()) {
        next_seq = tcp.seq_number + 1;
        started = true;
    }
    if (!started) {
        return;
    }
    if (tcp.fin()) {
        fin_seen = true;
        fin_seq = tcp.seq_number + static_cast<uint32_t>(span.size());
    }
    if (!span.empty()) {
        if (tcp.seq_number == next_seq) {
            assembled.insert(assembled.end(), span.begin(), span.end());
            next_seq += static_cast<uint32_t>(span.size());
            drain();
        } else if (static_cast<int32_t>(next_seq - tcp.seq_number) < 0) {
            queue_out_of_order(tcp.seq_number, span);
        } else {
            uint32_t overlap = next_seq - tcp.seq_number;
            if (overlap < span.size()) {
                assembled.insert(assembled.end(), span.begin() + overlap, span.end());
                next_seq += static_cast<uint32_t>(span.size() - overlap);
                drain();
            }
        }
    }
    drain();
    if (fin_seen && next_seq == fin_seq) {
        next_seq++;
        closed = true;
    }
}

void TcpReassembler::queue_out_of_order(uint32_t seq, std::span<const uint8_t> span) {
    std::vector<uint8_t> data(span.begin(), span.end());
    auto prev = out_of_order.upper_bound(seq);
    if (prev != out_of_order.begin()) {
        --prev;
        uint32_t prev_end = prev->first + static_cast<uint32_t>(prev->second.size());
        if (prev_end > seq) {
            uint32_t overlap = prev_end - seq;
            if (overlap >= data.size()) {
                return;
            }
            seq += overlap;
            data.erase(data.begin(), data.begin() + overlap);
        }
    }
    auto it = out_of_order.lower_bound(seq);
    while (it != out_of_order.end()) {
        uint32_t end = seq + static_cast<uint32_t>(data.size());
        if (it->first >= end) {
            break;
        }
        uint32_t it_end = it->first + static_cast<uint32_t>(it->second.size());
        if (it_end <= end) {
            ooo_bytes -= it->second.size();
            it = out_of_order.erase(it);
        } else {
            uint32_t overlap = end - it->first;
            std::vector<uint8_t> tail(it->second.begin() + overlap, it->second.end());
            ooo_bytes -= it->second.size();
            it = out_of_order.erase(it);
            ooo_bytes += tail.size();
            out_of_order.emplace(end, std::move(tail));
            break;
        }
    }
    if (data.empty()) {
        return;
    }
    if (ooo_bytes + data.size() > MAX_OOO_BYTES) {
        return;
    }
    ooo_bytes += data.size();
    out_of_order.emplace(seq, std::move(data));
}

size_t TcpReassembler::available() const noexcept {
    return assembled.size() - read_pos;
}

const std::span<const uint8_t> TcpReassembler::peek(size_t n) const {
    n = std::min(n, available());
    return std::span<const uint8_t>{assembled.data() + read_pos, n};
}

void TcpReassembler::consume(size_t n) {
    read_pos += std::min(n, available());
    if (read_pos > MIN_COMPACT_BYTES && read_pos > assembled.size() / 2) {
        assembled.erase(assembled.begin(), assembled.begin() + read_pos);
        read_pos = 0;
    }
}

void TcpReassembler::drain() {
    for (auto it = out_of_order.find(next_seq); it != out_of_order.end(); it = out_of_order.find(next_seq)) {
        assembled.insert(assembled.end(), it->second.begin(), it->second.end());
        next_seq += static_cast<uint32_t>(it->second.size());
        ooo_bytes -= it->second.size();
        out_of_order.erase(it);
    }
}

}