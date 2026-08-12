#pragma once

#include <net/analysis/dns_table.h>
#include <net/decode/app_decoder.h>
#include <net/flow/flow_tracker.h>

#include <ostream>
#include <string>

namespace net {

class StatsEngine {
public:
    StatsEngine(const FlowTable& flowTable, const AppDecoder& appDecoder, const DnsTable& dnsTable);

    std::string toString() const noexcept;
private:
    const FlowTable& flowTable_;
    const AppDecoder& appDecoder_;
    const DnsTable& dnsTable_;

    std::vector<std::pair<const FlowKey*, const FlowTable::Flow*>> sortedFlowsByBytes() const;
    std::vector<std::pair<uint8_t, uint64_t>> sortedProtocolsByBytes(std::vector<std::pair<const FlowKey*, const FlowTable::Flow*>> sortedFlow) const;
    void printFlow(std::ostream& os, const FlowKey& key, const FlowTable::Flow& flow) const;
};

std::ostream& operator<<(std::ostream& os, const StatsEngine& engine);

}
