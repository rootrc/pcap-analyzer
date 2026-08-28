#include "protocol_generator.h"

#include <cstring>
#include <stdexcept>

namespace testgen {

uint16_t checksum(const uint8_t* data, size_t len, uint64_t initial_sum) {
    uint64_t sum = initial_sum;
    
    for (size_t i = 0; i < len; i += 2) {
        if (i + 1 < len) {
            sum += (data[i] << 8) | data[i + 1];
        } else {
            sum += (data[i] << 8);
        }
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

void makeEthernetHeader(uint8_t* data, uint16_t ethertype) {
    net::ethernet::Header h{};
    for (int i = 0; i < 6; ++i) {
        h.dst_mac[i] = randomgen::rand8();
        h.src_mac[i] = randomgen::rand8();
    }
    h.ethertype = net::bswap16(ethertype);
    memcpy(data, &h, net::ethernet::HEADER_LEN);
}

void makeVlanHeader(uint8_t* data, uint16_t ethertype) {
    net::vlan::Header h{};
    do {
        h.tci = randomgen::rand32();
    } while (h.vid() == net::vlan::VID_RESERVED);
    h.tci = net::bswap16(h.tci);
    h.ethertype = net::bswap16(ethertype);
    memcpy(data, &h, net::vlan::HEADER_LEN);
}

void makeIPv4Header(uint8_t* data, uint8_t protocol, uint8_t ihl, uint16_t payload_len) {
    net::ip::v4::Header h{};

    if (ihl < net::ip::v4::MIN_IHL || ihl > net::ip::v4::MAX_IHL) {
        throw std::out_of_range("ihl out of range [5, 15]");
    }

    h.version_ihl = (net::ip::v4::SUPPORTED_VERSION << 4) | ihl;
    h.tos = 0;
    h.total_length = net::bswap16(h.header_length()  + payload_len);
    h.identification = randomgen::rand16();
    h.flags_fragment = net::bswap16(0x4000);
    h.ttl = randomgen::randRange8(32, 128);
    h.protocol = protocol;
    h.checksum = 0;
    h.src_ip = randomgen::rand32();
    h.dst_ip = randomgen::rand32();
    for (size_t i = net::ip::v4::MIN_HEADER_LEN; i < h.header_length(); ++i) {
        data[i] = randomgen::rand8();
    }

    memcpy(data, &h, net::ip::v4::MIN_HEADER_LEN);
    h.checksum = checksum(data, h.header_length());
    data[10] = h.checksum >> 8;
    data[11] = h.checksum & 0xFF;
}

void makeIPv6Header(uint8_t* data, uint8_t next_header, uint16_t payload_length) {
    net::ip::v6::Header h{};

    uint32_t tc = randomgen::rand8();
    uint32_t flow = randomgen::rand32() & 0xFFFFF;
    h.version_tc_fl = net::bswap32((net::ip::v6::SUPPORTED_VERSION << 28) | (tc << 20) | flow);
    h.payload_length = net::bswap16(payload_length);
    h.next_header = next_header;
    h.hop_limit = randomgen::randRange8(32, 128);
    for (int i = 0; i < 16; ++i) {
        h.src_ip[i] = randomgen::rand8();
        h.dst_ip[i] = randomgen::rand8();
    }
    memcpy(data, &h, net::ip::v6::HEADER_LEN);
}

void makeArpHeader(uint8_t* data) {
    net::arp::Header h{};

    h.htype = net::bswap16(net::arp::HTYPE_ETHERNET);
    h.ptype = net::bswap16(net::ethernet::ETHERTYPE_IPV4);
    h.hlen = sizeof(net::ethernet::Header::dst_mac);
    h.plen = sizeof(net::ip::v4::Header::src_ip);
    h.oper = net::bswap16(randomgen::randRange16(net::arp::OPER_REQUEST, net::arp::OPER_REPLY));
    for (size_t i = net::arp::MIN_HEADER_LEN; i < net::arp::MIN_HEADER_LEN + 2 * h.hlen + 2 * h.plen; ++i) {
        data[i] = randomgen::rand8();
    }
    memcpy(data, &h, net::arp::MIN_HEADER_LEN);
}

void makeTcpHeader(uint8_t* data, uint64_t pseudo_sum, uint8_t data_offset, size_t payload_len) {
    net::tcp::Header h{};

    if (data_offset < net::tcp::MIN_DATA_OFFSET || data_offset > net::tcp::MAX_DATA_OFFSET) {
        throw std::out_of_range("data_offset out of range [5, 15]");
    }

    h.src_port = randomgen::rand16();
    h.dst_port = randomgen::rand16();
    h.seq_number = randomgen::rand32();
    h.ack_number = randomgen::rand32();
    h.data_offset_reserved = data_offset << 4;
    h.flags = 0x18;
    h.window_size = net::bswap16(randomgen::randRange16(1024, 65535));
    h.checksum = 0;
    h.urgent_pointer = 0;
    for (size_t i = net::tcp::MIN_HEADER_LEN; i < h.header_length() + payload_len; ++i) {
        data[i] = randomgen::rand8();
    }

    memcpy(data, &h, net::tcp::MIN_HEADER_LEN);
    h.checksum = checksum(data, h.header_length() + payload_len, pseudo_sum);
    data[16] = h.checksum >> 8;
    data[17] = h.checksum & 0xFF;
}

void makeTcpHeader(uint8_t* data, const net::ip::v4::Header& ip, uint8_t data_offset, size_t payload_len) {
    makeTcpHeader(data, net::ip::v4::computePseudoHeaderSum(ip), data_offset, payload_len);
}

void makeTcpHeader(uint8_t* data, const net::ip::v6::Header& ip, uint8_t data_offset, size_t payload_len) {
    makeTcpHeader(data, net::ip::v6::computePseudoHeaderSum(ip), data_offset, payload_len);
}

void makeUdpHeader(uint8_t* data, uint64_t pseudo_sum, uint16_t udp_length) {
    net::udp::Header h{};

    h.src_port = randomgen::rand16();
    h.dst_port = randomgen::rand16();
    h.length = net::bswap16(udp_length);
    h.checksum = 0;

    memcpy(data, &h, net::udp::HEADER_LEN);
    h.checksum = checksum(data, udp_length, pseudo_sum);
    data[6] = h.checksum >> 8;
    data[7] = h.checksum & 0xFF;
}

void makeUdpHeader(uint8_t* data, const net::ip::v4::Header& ip, uint16_t payload_length) {
    makeUdpHeader(data, net::ip::v4::computePseudoHeaderSum(ip), net::udp::HEADER_LEN + payload_length);
}

void makeUdpHeader(uint8_t* data, const net::ip::v6::Header& ip, uint16_t payload_length) {
    makeUdpHeader(data, net::ip::v6::computePseudoHeaderSum(ip), net::udp::HEADER_LEN + payload_length);
}

void makeIcmpHeader(uint8_t* data, size_t payload_len) {
    using namespace net::icmp;
    net::icmp::Header h{};

    static constexpr uint8_t types[] = {
        TYPE_ECHO_REPLY, TYPE_UNREACHABLE, TYPE_SOURCE_QUENCH,
        TYPE_REDIRECT, TYPE_ECHO_REQUEST, TYPE_TTL_EXCEEDED,
        TYPE_PARAM_PROBLEM
    };
    h.type = types[std::rand() % (sizeof(types) / sizeof(types[0]))];
    switch (h.type) {
        case TYPE_UNREACHABLE: h.code = randomgen::randRange8(CODE_NET_UNREACHABLE, CODE_PORT_UNREACHABLE); break;
        case TYPE_REDIRECT: h.code = randomgen::randRange8(CODE_REDIRECT_NET, CODE_REDIRECT_TOS_HOST); break;
        case TYPE_TTL_EXCEEDED: h.code = randomgen::randRange8(CODE_TTL_IN_TRANSIT, CODE_TTL_REASSEMBLY); break;
        case TYPE_PARAM_PROBLEM: h.code = randomgen::randRange8(CODE_PARAM_BAD_HEADER, CODE_PARAM_MISSING_OPT); break;
        default: h.code = 0; break;
    }
    if (h.type == TYPE_ECHO_REQUEST || h.type == TYPE_ECHO_REPLY) {
        h.echo.id = randomgen::rand16();
        h.echo.seq = randomgen::rand16();
    } else if (h.type == TYPE_REDIRECT) {
        h.gateway = randomgen::rand32();
    } else if (h.type == TYPE_PARAM_PROBLEM) {
        h.param_problem.pointer = randomgen::rand8();
    }
    for (size_t i = HEADER_LEN; i < HEADER_LEN + payload_len; ++i) {
        data[i] = randomgen::rand8();
    }
    
    memcpy(data, &h, HEADER_LEN);
    h.checksum = checksum(data, HEADER_LEN + payload_len);
    data[2] = h.checksum >> 8;
    data[3] = h.checksum & 0xFF;
}

void makeIcmpv6Header(uint8_t* data, const net::ip::v6::Header& ip, size_t payload_len) {
    using namespace net::icmpv6;
    net::icmpv6::Header h{};

    static constexpr uint8_t types[] = {
        TYPE_UNREACHABLE, TYPE_PACKET_TOO_BIG, TYPE_TTL_EXCEEDED,
        TYPE_PARAM_PROBLEM, TYPE_ECHO_REQUEST, TYPE_ECHO_REPLY
    };
    h.type = types[std::rand() % (sizeof(types) / sizeof(types[0]))];
    switch (h.type) {
        case TYPE_UNREACHABLE: h.code = randomgen::randRange8(CODE_UNREACH_NO_ROUTE, CODE_UNREACH_PORT); break;
        case TYPE_TTL_EXCEEDED: h.code = randomgen::randRange8(CODE_TTL_IN_TRANSIT, CODE_TTL_REASSEMBLY); break;
        case TYPE_PARAM_PROBLEM: h.code = randomgen::randRange8(CODE_PARAM_BAD_HEADER, CODE_PARAM_UNKNOWN_OPTION); break;
        default: h.code = 0; break;
    }
    if (h.type == TYPE_ECHO_REQUEST || h.type == TYPE_ECHO_REPLY) {
        h.echo.id = randomgen::rand16();
        h.echo.seq = randomgen::rand16();
    } else if (h.type == TYPE_PACKET_TOO_BIG) {
        h.mtu = net::bswap32(randomgen::randRange32(net::icmpv6::MIN_MTU, 9000));
    } else if (h.type == TYPE_PARAM_PROBLEM) {
        h.pointer = randomgen::rand32();
    }
    for (size_t i = HEADER_LEN; i < HEADER_LEN + payload_len; ++i) {
        data[i] = randomgen::rand8();
    }
    
    memcpy(data, &h, HEADER_LEN);
    h.checksum = checksum(data, HEADER_LEN + payload_len, net::ip::v6::computePseudoHeaderSum(ip));
    data[2] = h.checksum >> 8;
    data[3] = h.checksum & 0xFF;
}

void makeDnsHeader(uint8_t* data) {
    static constexpr const char* names[] = {
        "example.com", "foo.bar.com", "mail.example.org",
        "test.local", "api.service.net", "cdn.example.io",
    };
    static constexpr const char* tlds[] = { "com", "net", "org", "io", "dev" };
    static constexpr const char* words[] = {
        "mail", "api", "cdn", "www", "auth", "shop", "blog", "app",
    };
    static constexpr const char* txts[] = {
        "v=spf1 include:example.com ~all",
        "google-site-verification=abc123",
        "MS=ms12345678",
    };

    auto writeName = [](uint8_t* data, size_t pos, const char* name) {
        const char* p = name;
        while (*p) {
            const char* dot = p;
            while (*dot && *dot != '.') dot++;
            uint8_t len = static_cast<uint8_t>(dot - p);
            data[pos++] = len;
            std::memcpy(data + pos, p, len);
            pos += len;
            p = (*dot == '.') ? dot + sizeof(uint8_t) : dot;
        }
        data[pos++] = 0;
        return pos;
    };
    auto writeRRHeader = [&](size_t pos, uint16_t type, uint32_t ttl, uint16_t rdlength) {
        net::dns::WireResourceHeader wrr{};
        wrr.type = net::bswap16(type);
        wrr.rclass = net::bswap16(net::dns::CLASS_IN);
        wrr.ttl = net::bswap32(ttl);
        wrr.rdlength = net::bswap16(rdlength);
        std::memcpy(data + pos, &wrr, sizeof(wrr));
        return pos + sizeof(wrr);
    };
    auto writeNamePtr = [&](size_t pos) {
        data[pos++] = net::dns::DnsCompressionPointerMask;
        data[pos++] = net::dns::HEADER_LEN;
        return pos;
    };

    const char* name = names[std::rand() % (sizeof(names) / sizeof(names[0]))];
    uint32_t ttl = randomgen::randRange16(30, 3600);

    enum Case { QUERY, NXDOMAIN, A, MULTI_A, AAAA, CNAME, PTR, TXT, MX, CASE_COUNT };
    int rtype = std::rand() % CASE_COUNT;

    uint16_t qtype = net::dns::TYPE_A;
    uint16_t ancount = 0;
    uint16_t flags = 0x8180;

    if (rtype == QUERY) {
        static constexpr uint16_t qtypes[] = {
            net::dns::TYPE_A, net::dns::TYPE_AAAA, net::dns::TYPE_MX,
            net::dns::TYPE_TXT, net::dns::TYPE_CNAME, net::dns::TYPE_PTR,
        };
        qtype = qtypes[std::rand() % (sizeof(qtypes) / sizeof(qtypes[0]))];
        flags = 0x0100;
    } else if (rtype == NXDOMAIN) {
        flags = 0x8183;
    } else if (rtype == A) { qtype = net::dns::TYPE_A; ancount = 1; }
    else if (rtype == MULTI_A) { qtype = net::dns::TYPE_A; ancount = randomgen::randRange8(2, 4); }
    else if (rtype == AAAA) { qtype = net::dns::TYPE_AAAA; ancount = 1; }
    else if (rtype == CNAME) { qtype = net::dns::TYPE_CNAME; ancount = 1; }
    else if (rtype == PTR) { qtype = net::dns::TYPE_PTR; ancount = 1; }
    else if (rtype == TXT) { qtype = net::dns::TYPE_TXT; ancount = 1; }
    else if (rtype == MX) { qtype = net::dns::TYPE_MX; ancount = 1; }

    net::dns::WireHeader h{};
    h.id = randomgen::rand16();
    h.flags = net::bswap16(flags);
    h.qdcount = net::bswap16(1);
    h.ancount = net::bswap16(ancount);
    std::memcpy(data, &h, net::dns::HEADER_LEN);

    size_t pos = net::dns::HEADER_LEN;
    pos = writeName(data, pos, name);

    net::dns::WireQuestion wq{};
    wq.qtype = net::bswap16(qtype);
    wq.qclass = net::bswap16(net::dns::CLASS_IN);
    std::memcpy(data + pos, &wq, sizeof(wq));
    pos += sizeof(wq);

    if (rtype == QUERY || rtype == NXDOMAIN) return;

    if (rtype == A || rtype == MULTI_A) {
        for (uint16_t i = 0; i < ancount; ++i) {
            pos = writeNamePtr(pos);
            pos = writeRRHeader(pos, net::dns::TYPE_A, ttl, sizeof(net::ip::v4::Header::src_ip));
            uint32_t ip = randomgen::rand32();
            std::memcpy(data + pos, &ip, sizeof(net::ip::v4::Header::src_ip));
            pos += sizeof(net::ip::v4::Header::src_ip);
        }
    } else if (rtype == AAAA) {
        pos = writeNamePtr(pos);
        pos = writeRRHeader(pos, net::dns::TYPE_AAAA, ttl, sizeof(net::ip::v6::Header::src_ip));
        for (int i = 0; i < sizeof(net::ip::v6::Header::src_ip); ++i) data[pos++] = randomgen::rand8();
    } else if (rtype == CNAME) {
        char cname[64];
        std::snprintf(cname, sizeof(cname), "%s.%s",
            words[std::rand() % (sizeof(words) / sizeof(words[0]))],
            tlds[std::rand() % (sizeof(tlds) / sizeof(tlds[0]))]);
        pos = writeNamePtr(pos);
        size_t rdata_start = pos + sizeof(net::dns::WireResourceHeader);
        size_t rdata_end = writeName(data, rdata_start, cname);
        pos = writeRRHeader(pos, net::dns::TYPE_CNAME, ttl, static_cast<uint16_t>(rdata_end - rdata_start));
        pos = rdata_end;
    } else if (rtype == PTR) {
        char ptr[64];
        std::snprintf(ptr, sizeof(ptr), "%s.%s",
            words[std::rand() % (sizeof(words) / sizeof(words[0]))],
            tlds[std::rand() % (sizeof(tlds) / sizeof(tlds[0]))]);
        pos = writeNamePtr(pos);
        size_t rdata_start = pos + sizeof(net::dns::WireResourceHeader);
        size_t rdata_end = writeName(data, rdata_start, ptr);
        pos = writeRRHeader(pos, net::dns::TYPE_PTR, ttl, static_cast<uint16_t>(rdata_end - rdata_start));
        pos = rdata_end;
    } else if (rtype == TXT) {
        const char* txt = txts[std::rand() % (sizeof(txts) / sizeof(txts[0]))];
        uint8_t len = static_cast<uint8_t>(std::strlen(txt));
        pos = writeNamePtr(pos);
        pos = writeRRHeader(pos, net::dns::TYPE_TXT, ttl, len + 1);
        data[pos++] = len;
        std::memcpy(data + pos, txt, len);
        pos += len;
    } else if (rtype == MX) {
        char mx[64];
        std::snprintf(mx, sizeof(mx), "mail.%s",
            tlds[std::rand() % (sizeof(tlds) / sizeof(tlds[0]))]);
        uint16_t priority = randomgen::randRange16(10, 50);
        pos = writeNamePtr(pos);
        size_t rdata_start = pos + sizeof(net::dns::WireResourceHeader);
        std::memcpy(data + rdata_start, &priority, sizeof(uint16_t));
        size_t rdata_end = writeName(data, rdata_start + sizeof(uint16_t), mx);
        pos = writeRRHeader(pos, net::dns::TYPE_MX, ttl, static_cast<uint16_t>(rdata_end - rdata_start));
        pos = rdata_end;
    }
}

std::string randomToken(size_t min_len = 3, size_t max_len = 12) {
    static constexpr char tchars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        "!#$%&'*+.^_`|~";
    size_t len = min_len + (static_cast<size_t>(std::rand()) % (max_len - min_len + 1));
    std::string s(len, '\0');
    for (size_t i = 0; i < len; ++i) {
        s[i] = tchars[std::rand() % (sizeof(tchars) - 1)];
    }
    return s;
}

std::string randomFieldValue(size_t min_len = 0, size_t max_len = 20) {
    size_t len = min_len + (static_cast<size_t>(std::rand()) % (max_len - min_len + 1));
    std::string s(len, '\0');
    for (size_t i = 0; i < len; ++i) {
        s[i] = static_cast<char>(0x21 + (std::rand() % (0x7E - 0x21 + 1)));
    }
    return s;
}

int appendRandomFields(char* buf, int pos, size_t buf_size, int min_count = 0, int max_count = 100) {
    int count = min_count + std::rand() % (max_count - min_count + 1);
    for (int i = 0; i < count; ++i) {
        pos += std::snprintf(buf + pos, buf_size - static_cast<size_t>(pos), "%s: %s\r\n", randomToken().c_str(), randomFieldValue().c_str());
    }
    return pos;
}

void makeHttpRequest(uint8_t* data) {
    static constexpr std::string_view methods[] = { "GET", "POST", "PUT", "DELETE", "HEAD" };
    static constexpr std::string_view targets[] = {"/", "/index.html", "/api/users", "/api/users/42", "/search?q=test" };
    static constexpr std::string_view hosts[] = { "example.com", "api.service.net", "cdn.example.io" };
    static constexpr std::string_view bodies[] = {"{\"ok\":true}", "hello=world&foo=bar", "some plain text body" };

    std::string_view method = methods[std::rand() % (sizeof(methods) / sizeof(methods[0]))];
    std::string_view target = targets[std::rand() % (sizeof(targets) / sizeof(targets[0]))];
    std::string_view host = hosts[std::rand() % (sizeof(hosts) / sizeof(hosts[0]))];

    char buf[16384];
    int pos = std::snprintf(buf, sizeof(buf), "%.*s %.*s HTTP/1.1\r\nHost: %.*s\r\nUser-Agent: testgen/1.0\r\n",
                             static_cast<int>(method.size()), method.data(),
                             static_cast<int>(target.size()), target.data(),
                             static_cast<int>(host.size()), host.data());
    pos = appendRandomFields(buf, pos, sizeof(buf));

    enum BodyKind { NONE, FIXED, CHUNKED, BODY_KIND_COUNT };
    bool allow_body = method != "GET" && method != "HEAD";
    int body_kind = allow_body ? std::rand() % BODY_KIND_COUNT : NONE;
    std::string_view body = bodies[std::rand() % (sizeof(bodies) / sizeof(bodies[0]))];

    if (body_kind == FIXED) {
        pos += std::snprintf(buf + pos, sizeof(buf) - pos, "Content-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%.*s", body.size(), static_cast<int>(body.size()), body.data());
    } else if (body_kind == CHUNKED) {
        pos += std::snprintf(buf + pos, sizeof(buf) - pos, "Transfer-Encoding: chunked\r\n\r\n");
        size_t half = body.size() / 2;
        if (half == 0) {
            pos += std::snprintf(buf + pos, sizeof(buf) - pos, "%zx\r\n%.*s\r\n0\r\n\r\n", body.size(), static_cast<int>(body.size()), body.data());
        } else {
            pos += std::snprintf(buf + pos, sizeof(buf) - pos, "%zx\r\n%.*s\r\n", half, static_cast<int>(half), body.data());
            pos += std::snprintf(buf + pos, sizeof(buf) - pos, "%zx\r\n%.*s\r\n0\r\n\r\n", body.size() - half, static_cast<int>(body.size() - half), body.data() + half);
        }
    } else {
        pos += std::snprintf(buf + pos, sizeof(buf) - pos, "\r\n");
    }

    std::memcpy(data, buf, static_cast<size_t>(pos));
}

void makeHttpResponse(uint8_t* data) {
    struct StatusLine { uint16_t code; std::string_view reason; };
    static constexpr StatusLine statuses[] = {
        {200, "OK"}, {201, "Created"}, {204, "No Content"},
        {301, "Moved Permanently"}, {304, "Not Modified"},
        {400, "Bad Request"}, {404, "Not Found"}, {500, "Internal Server Error"},
    };
    static constexpr std::string_view bodies[] = { "{\"ok\":true}", "<html><body>hi</body></html>" };

    const StatusLine& status = statuses[std::rand() % (sizeof(statuses) / sizeof(statuses[0]))];
    bool bodyless = status.code == 204 || status.code == 304;
    std::string_view body = bodies[std::rand() % (sizeof(bodies) / sizeof(bodies[0]))];
    bool chunked = !bodyless && (std::rand() % 2 == 0);

    char buf[16384];
    int pos = std::snprintf(buf, sizeof(buf), "HTTP/1.1 %u %.*s\r\nServer: testgen\r\n", status.code, static_cast<int>(status.reason.size()), status.reason.data());
    pos = appendRandomFields(buf, pos, sizeof(buf));

    if (bodyless) {
        pos += std::snprintf(buf + pos, sizeof(buf) - pos, "\r\n");
    } else if (chunked) {
        pos += std::snprintf(buf + pos, sizeof(buf) - pos, "Transfer-Encoding: chunked\r\n\r\n");
        pos += std::snprintf(buf + pos, sizeof(buf) - pos, "%zx\r\n%.*s\r\n0\r\n\r\n",
                              body.size(), static_cast<int>(body.size()), body.data());
    } else {
        pos += std::snprintf(buf + pos, sizeof(buf) - pos, "Content-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%.*s", body.size(), static_cast<int>(body.size()), body.data());
    }

    std::memcpy(data, buf, static_cast<size_t>(pos));
}

void makeHttpHeader(uint8_t* data) {
    if (std::rand() % 2 == 0) makeHttpRequest(data);
    else makeHttpResponse(data);
    makeHttpResponse(data);
}

}