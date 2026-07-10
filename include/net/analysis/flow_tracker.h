#pragma once

#include <net/capture/packet.h>

#include <cstring>
#include <unordered_map>

namespace net {
    #pragma pack(push, 1)
    struct FlowKey {
        bool isIpv4;
        uint8_t src_ip[16];
        uint8_t dst_ip[16];
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t protocol;

        bool operator==(const FlowKey& o) const noexcept {
            return memcmp(src_ip, o.src_ip, 16) == 0 &&
                   memcmp(dst_ip, o.dst_ip, 16) == 0 &&
                   src_port == o.src_port &&
                   dst_port == o.dst_port &&
                   protocol == o.protocol;
        }

        bool normalize() noexcept {
            int cmp = memcmp(src_ip, dst_ip, 16);
            if (cmp > 0 || (cmp == 0 && src_port > dst_port)) {
                std::swap(src_port, dst_port);
                uint8_t tmp[16];
                memcpy(tmp, src_ip, 16);
                memcpy(src_ip, dst_ip, 16);
                memcpy(dst_ip, tmp, 16);
                return true;
            }
            return false;
        }
    };
    #pragma pack(pop)

    struct FlowKeyHash {
        size_t operator()(const FlowKey& k) const noexcept {
            size_t h = 14695981039346656037ULL;
            const uint8_t* p = reinterpret_cast<const uint8_t*>(&k);
            for (size_t i = 0; i < sizeof(FlowKey); ++i) {
                h ^= p[i];
                h *= 1099511628211ULL;
            }
            return h;
        }
    };

    std::ostream& operator<<(std::ostream& os, const FlowKey& key);

    struct FlowStats {
        uint64_t packets = 0;
        uint64_t bytes = 0;
    };

    struct Flow {
        uint64_t first_seen = 0;
        uint64_t last_seen = 0;
        FlowStats fwd;
        FlowStats rev;

        constexpr uint64_t totalPackets() const noexcept { return fwd.packets + rev.packets; }
        constexpr uint64_t totalBytes() const noexcept { return fwd.bytes + rev.bytes; }
        constexpr uint64_t durationUs() const noexcept { return last_seen - first_seen; }

        double payloadPercent(uint64_t total_bytes_all) const {
            if (total_bytes_all == 0) return 0.0;
            return 100.0 * static_cast<double>(totalBytes()) / static_cast<double>(total_bytes_all);
        }
    };

    class FlowTable {
    public:
        FlowTable() = default;

        ParseError addPacket(const Packet& pkt, uint64_t ts_us);
        void flush();

        const std::unordered_map<FlowKey, Flow, FlowKeyHash>& flows() const { return flows_; }
        const std::vector<std::pair<FlowKey, Flow>>& completed() const { return completed_; }
        uint64_t total_bytes() const { return total_bytes_; }

    private:
        static constexpr uint64_t IDLE_TIMEOUT_US = 30000000;
        static constexpr uint64_t ACTIVE_TIMEOUT_US = 120000000;

        uint64_t total_bytes_ = 0;
        std::unordered_map<FlowKey, Flow, FlowKeyHash> flows_;
        std::vector<std::pair<FlowKey, Flow>> completed_;

        ParseError keyFromPacket(const Packet& pkt, FlowKey& out, bool& is_reverse);
        bool setPorts(const net::Packet::TransportHeader transport, FlowKey& out);
        bool setNetwork(const net::Packet::NetworkHeader network, FlowKey& out);
        
        bool isExpired(const Flow& flow, uint64_t ts_us) const;
        
        void printFlow(std::ostream& os, const FlowKey& key, const Flow& flow) const;
        std::vector<std::pair<const FlowKey*, const Flow*>> sortedFlowsByBytes() const;
        std::vector<std::pair<uint8_t, uint64_t>> sortedProtocolsByBytes(std::vector<std::pair<const FlowKey*, const Flow*>> sortedFlow) const;
        friend std::ostream& operator<<(std::ostream& os, const FlowTable& table);
    };

    std::ostream& operator<<(std::ostream& os, const FlowTable& table);
}
