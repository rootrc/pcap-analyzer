#include <net/protocols/ethernet.h>

#include <cstring>
#include <iomanip>

namespace net::ethernet {
    ParseError parse(BufferView& buf, Header& header, Endian endian) {
        if (buf.length() < HEADER_LEN) return ParseError::UnexpectedEof;
        std::memcpy(&header, buf.current(), HEADER_LEN);

        header.ethertype = toHost16(header.ethertype, endian);
        
        buf.advance(HEADER_LEN);
        return ParseError::None;
    }
    std::ostream& operator<<(std::ostream& os, const Header& h) {
        os << "EthernetHeader {\n";
        os << "  dst_mac: ";
        for (int i = 0; i < 6; i++) {
            os << std::hex << std::setfill('0') << std::setw(2) << (int)h.dst_mac[i] << std::dec;
            if (i < 5) os << ":";
        }
        os << "\n";
        os << "  src_mac: ";
        for (int i = 0; i < 6; i++) {
            os << std::hex << std::setfill('0') << std::setw(2) << (int)h.src_mac[i] << std::dec;
            if (i < 5) os << ":";
        }
        os << "\n";
        os << "  ethertype: 0x" << std::hex << std::setfill('0') << std::setw(4) << h.ethertype << std::dec << "\n";
        os << "}";
        return os;
    }
}