#include <net/protocols/dns.h>
#include <net/protocols/ipv4.h>
#include <net/protocols/ipv6.h>

#include <cstring>
#include <iomanip>
#include <sstream>

namespace net::dns {

ParseError parseName(std::span<const uint8_t>& span, const uint8_t* dns_base, std::string& name, Endian endian) {
    name.clear();
    const uint8_t* dns_end = span.data() + span.size();
    const uint8_t* cur = span.data();
    int jumps = 0;

    while (cur < dns_end) {
        if (*cur == 0) {
            if (!jumps) span = span.subspan(static_cast<size_t>(cur - span.data() + sizeof(uint8_t)));
            return ParseError::None;
        }
        if ((*cur & DnsCompressionPointerMask) == DnsCompressionPointerMask) {
            if (cur + 1 >= dns_end) return ParseError::UnexpectedEof;
            if (++jumps > MaxDnsCompressionJumps ) return ParseError::MalformedHeader;
            if (jumps == 1) span = span.subspan(static_cast<size_t>(cur - span.data() + sizeof(uint16_t)));
            cur = dns_base + (((*cur & 0x3F) << 8) | *(cur + 1));
            continue;
        }
        if ((*cur & DnsCompressionPointerMask) != 0) return ParseError::MalformedHeader;

        uint8_t len = *cur;
        cur++;
        if (cur + len > dns_end) return ParseError::UnexpectedEof;
        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char*>(cur), len);
        cur += len;
    }
    return ParseError::UnexpectedEof;
}

ParseError parseQuestion(std::span<const uint8_t>& span, const uint8_t* dns_base, Question& q, Endian endian) {
    if (auto err = parseName(span, dns_base, q.name, endian); err != ParseError::None) return err;
    if (span.size() < QUESTION_HEADER_LEN) return ParseError::UnexpectedEof;
    WireQuestion wq;
    std::memcpy(&wq, span.data(), QUESTION_HEADER_LEN);
    q.qtype = toHost16(wq.qtype, endian);
    q.qclass = toHost16(wq.qclass, endian);
    span = span.subspan(QUESTION_HEADER_LEN);
    return ParseError::None;
}

ParseError parseResourceRecord(std::span<const uint8_t>& span, const uint8_t* dns_base, ResourceRecord& rr, Endian endian) {
    if (auto err = parseName(span, dns_base, rr.name, endian); err != ParseError::None) return err;
    if (span.size() < RESOURCE_HEADER_LEN) return ParseError::UnexpectedEof;
    WireResourceHeader wrr;
    std::memcpy(&wrr, span.data(), RESOURCE_HEADER_LEN);
    rr.type = toHost16(wrr.type, endian);
    rr.rclass = toHost16(wrr.rclass, endian);
    rr.ttl = toHost32(wrr.ttl, endian);
    uint16_t rdlength = toHost16(wrr.rdlength, endian);
    span = span.subspan(RESOURCE_HEADER_LEN);
    if (span.size() < rdlength) return ParseError::UnexpectedEof;
    rr.rdata.assign(span.data(), span.data() + rdlength);
    span = span.subspan(rdlength);
    return ParseError::None;
}

ParseError parse(std::span<const uint8_t>& span, Header& header, Endian endian) {
    if (span.size() < HEADER_LEN) return ParseError::UnexpectedEof;
    WireHeader wire;
    std::memcpy(&wire, span.data(), HEADER_LEN);
    header.id = toHost16(wire.id, endian);
    header.flags = toHost16(wire.flags, endian);
    header.qdcount = toHost16(wire.qdcount, endian);
    header.ancount = toHost16(wire.ancount, endian);
    header.nscount = toHost16(wire.nscount, endian);
    header.arcount = toHost16(wire.arcount, endian);
    const uint8_t* dns_base = span.data();
    span = span.subspan(HEADER_LEN);

    header.questions.resize(header.qdcount);
    for (net::dns::Question& q : header.questions) {
        if (auto err = parseQuestion(span, dns_base, q, endian); err != ParseError::None) return err;
    }
    header.answers.resize(header.ancount);
    for (net::dns::ResourceRecord& rr : header.answers) {
        if (auto err = parseResourceRecord(span, dns_base, rr, endian); err != ParseError::None) return err;
    }
    header.authority.resize(header.nscount);
    for (net::dns::ResourceRecord& rr : header.authority) {
        if (auto err = parseResourceRecord(span, dns_base, rr, endian); err != ParseError::None) return err;
    }
    header.additional.resize(header.arcount);
    for (net::dns::ResourceRecord& rr : header.additional) {
        if (auto err = parseResourceRecord(span, dns_base, rr, endian); err != ParseError::None) return err;
    }
    return ParseError::None;
}

const char* typeName(uint16_t type) {
    switch (type) {
        case TYPE_A: return "A";
        case TYPE_NS: return "NS";
        case TYPE_CNAME: return "CNAME";
        case TYPE_SOA: return "SOA";
        case TYPE_PTR: return "PTR";
        case TYPE_MX: return "MX";
        case TYPE_TXT: return "TXT";
        case TYPE_AAAA: return "AAAA";
        case TYPE_SRV: return "SRV";
        default: return "?";
    }
}

std::string Header::toString() const noexcept {
    std::ostringstream oss;
    oss << "DNSHeader {\n"
        << "  id: " << id << '\n'
        << "  flags: " << (isResponse() ? "response" : "query");
    if (isAA()) oss << " AA";
    if (isTC()) oss << " TC";
    if (isRD()) oss << " RD";
    if (isRA()) oss << " RA";
    oss << "  rcode=" << static_cast<int>(rcode()) << '\n';

    for (const net::dns::Question& q : questions) {
        oss << "  ? " << q.name << " " << typeName(q.qtype) << '\n';
    }
    for (const auto& rr : answers) {
        oss << "  " << typeName(rr.type) << " " << rr.name << " ttl=" << rr.ttl << " ";
        if (rr.type == TYPE_A && rr.rdata.size() == 4) {
            ip::v4::printIp(oss, rr.rdata.data());
        } else if (rr.type == TYPE_AAAA && rr.rdata.size() == 16) {
            ip::v6::printIp(oss, rr.rdata.data());
        } else if (rr.type == TYPE_TXT && !rr.rdata.empty()) {
            uint8_t len = rr.rdata[0];
            oss << '"';
            oss.write(reinterpret_cast<const char*>(rr.rdata.data() + 1), std::min((size_t)len, rr.rdata.size() - 1));
            oss << '"';
        } else {
            auto f = oss.flags();
            oss << std::hex << std::setfill('0');
            for (uint8_t b : rr.rdata) oss << std::setw(2) << static_cast<int>(b);
            oss.flags(f);
        }
        oss << '\n';
    }
    oss << "}";
    return oss.str();
}

std::string Header::toJson() const noexcept {
    std::ostringstream oss;
    oss << "\"dns\": {\n"
        << "  \"id\": " << id << ",\n"
        << "  \"flags\": ["
        << '"' << (isResponse() ? "response" : "query") << '"';
    if (isAA()) { oss << ", "; oss << "\"AA\""; }
    if (isTC()) { oss << ", "; oss << "\"TC\""; }
    if (isRD()) { oss << ", "; oss << "\"RD\""; }
    if (isRA()) { oss << ", "; oss << "\"RA\""; }
    oss << "],\n"
        << "  \"rcode\": " << static_cast<int>(rcode()) << ",\n";

    if (questions.empty()) {
        oss << "  \"questions\": [],\n";
    } else {
        oss << "  \"questions\": [\n";
        for (size_t i = 0; i < questions.size(); ++i) {
            if (i) oss << ",\n";
            oss << "    {\n"
                << "      \"name\": \"" << questions[i].name << "\",\n"
                << "      \"type\": \"" << typeName(questions[i].qtype) << "\"\n"
                << "    }";
        }
        oss << "\n  ],\n";
    }
    if (answers.empty()) {
        oss << "  \"answers\": []\n";
    } else {
        oss << "  \"answers\": [\n";
        for (size_t i = 0; i < answers.size(); ++i) {
            if (i) oss << ",\n";
            const ResourceRecord& rr = answers[i];
            oss << "    {\n"
                << "      \"type\": \"" << typeName(rr.type) << "\",\n"
                << "      \"name\": \"" << rr.name << "\",\n"
                << "      \"ttl\": " << rr.ttl << ",\n"
                << "      \"rdata\": \"";
            if (rr.type == TYPE_A && rr.rdata.size() == 4) {
                ip::v4::printIp(oss, rr.rdata.data());
            } else if (rr.type == TYPE_AAAA && rr.rdata.size() == 16) {
                ip::v6::printIp(oss, rr.rdata.data());
            } else {
                auto f = oss.flags();
                oss << std::hex << std::setfill('0');
                for (uint8_t b : rr.rdata) oss << std::setw(2) << static_cast<int>(b);
                oss.flags(f);
            }
            oss << "\"\n    }";
        }
        oss << "\n  ]\n";
    }
    oss << "}";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    return os << h.toString();
}

}