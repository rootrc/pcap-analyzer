#pragma once

#include <net/protocols/dns.h>

#include <unordered_map>

namespace net {

class DnsTable {
public:
    struct IpKey {
        bool isIpv4 = false;
        uint8_t ip[16] = {};

        bool operator==(const IpKey& other) const noexcept;
    };

    struct IpKeyHash {
        size_t operator()(const IpKey& key) const noexcept;
    };

    void record(const dns::Header& message);

    const std::vector<std::string>* domainsFor(const uint8_t ip[16], bool isIpv4) const;
    const std::unordered_map<IpKey, std::vector<std::string>, IpKeyHash>& domainsByIp() const { return domains_by_ip_; }

    size_t size() const;

private:
    std::unordered_map<IpKey, std::vector<std::string>, IpKeyHash> domains_by_ip_;

    void recordRecords(const std::vector<dns::ResourceRecord>& records);
};

}
