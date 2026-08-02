#include <net/analysis/dns_table.h>

#include <algorithm>
#include <cstring>
#include <iostream>

namespace net {

bool DnsTable::IpKey::operator==(const IpKey& other) const noexcept {
    return isIpv4 == other.isIpv4 && std::memcmp(ip, other.ip, sizeof(ip)) == 0;
}

size_t DnsTable::IpKeyHash::operator()(const IpKey& key) const noexcept {
    size_t h = 14695981039346656037ULL;
    h ^= static_cast<size_t>(key.isIpv4);
    h *= 1099511628211ULL;
    for (uint8_t byte : key.ip) {
        h ^= byte;
        h *= 1099511628211ULL;
    }
    return h;
}

void DnsTable::record(const dns::Header& message) {
    if (!message.isResponse()) {
        return;
    }
    recordRecords(message.answers);
    recordRecords(message.additional);
}

void DnsTable::recordRecords(const std::vector<dns::ResourceRecord>& records) {
    for (const dns::ResourceRecord& rr : records) {
        IpKey key{};
        if (rr.type == dns::TYPE_A && rr.rdata.size() == 4) {
            key.isIpv4 = true;
            std::memcpy(key.ip, rr.rdata.data(), 4);
        } else if (rr.type == dns::TYPE_AAAA && rr.rdata.size() == 16) {
            key.isIpv4 = false;
            std::memcpy(key.ip, rr.rdata.data(), 16);
        } else {
            continue;
        }

        std::vector<std::string>& names = domains_by_ip_[key];
        if (std::find(names.begin(), names.end(), rr.name) == names.end()) {
            names.push_back(rr.name);
        }
    }
}

const std::vector<std::string>* DnsTable::domainsFor(const uint8_t ip[16], bool isIpv4) const {
    IpKey key{};
    key.isIpv4 = isIpv4;
    std::memcpy(key.ip, ip, sizeof(key.ip));

    auto it = domains_by_ip_.find(key);
    return it != domains_by_ip_.end() ? &it->second : nullptr;
}

size_t DnsTable::size() const {
    return domains_by_ip_.size();
}

}
