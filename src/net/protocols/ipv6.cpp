#include <net/protocols/ipv6.h>
#include <net/core/checksum.h>

#include <cstring>
#include <iomanip>

namespace net::ip::v6 {
    size_t parse(BufferView& buf, Header& header, Endian endian) {
        if (buf.length() < HEADER_LEN) return 0;
        std::memcpy(&header, buf.current(), HEADER_LEN);

        header.version_tc_fl = toHost32(header.version_tc_fl, endian);
        header.payload_length = toHost16(header.payload_length, endian);

        uint32_t version = header.version_tc_fl >> 28;
        if (version != 6) {
            return 0;
        }

        buf.advance(HEADER_LEN);
        return HEADER_LEN;
    }
    uint64_t computePseudoHeaderSum(const Header& header) {
        uint64_t sum = 0;

        // TODO: Verify checksum
        for (int i = 0; i < 16; i += 2) {
            sum += (header.src_ip[i] << 8) | header.src_ip[i + 1];
        }

        for (int i = 0; i < 16; i += 2) {
            sum += (header.dst_ip[i] << 8) | header.dst_ip[i + 1];
        }

        uint16_t payload_length = bswap16(payload_length);
        sum += (header.payload_length >> 16);
        sum += header.payload_length;
        sum += header.next_header;
        return sum;
    }

    std::ostream& operator<<(std::ostream& os, const Header& h) {
        os << "IPv6Header {\n";
        os << "  version: " << (h.version_tc_fl >> 28) << "\n";
        os << "  traffic_class: " << ((h.version_tc_fl >> 20) & 0xFF) << "\n";
        os << "  flow_label: " << std::hex << (h.version_tc_fl & 0xFFFFF) << std::dec << "\n";
        os << "  payload_length: " << h.payload_length << "\n";
        os << "  next_header: " << (int)h.next_header << "\n";
        os << "  hop_limit: " << (int)h.hop_limit << "\n";
        os << "  src_ip: ";
        for (int i = 0; i < 16; i++) {
            os << std::hex << std::setfill('0') << std::setw(2) << (int)h.src_ip[i] << std::dec;
            if (i < 15) os << ":";
        }
        os << "\n";
        os << "  dst_ip: ";
        for (int i = 0; i < 16; i++) {
            os << std::hex << std::setfill('0') << std::setw(2) << (int)h.dst_ip[i] << std::dec;
            if (i < 15) os << ":";
        }
        os << "\n";
        os << "}";
        return os;
    }
}