#pragma once

#include <string_view>

namespace net {

enum class ParseError {
    None,
    UnexpectedEofF,
    UnexpectedEof,
    UnsupportedVersion,
    UnsupportedLinktype,
    UnsupportedNetworkType,
    UnsupportedTransportType,
    MalformedHeader,
    InvalidFieldValue,
    ChecksumMismatch,
};

constexpr std::string_view toString(ParseError e) {
    switch (e) {
        case ParseError::None: return "no error";
        case ParseError::UnexpectedEofF: return "unexpected end of file";
        case ParseError::UnexpectedEof: return "unexpected end of buffer";
        case ParseError::UnsupportedVersion: return "unsupported version";
        case ParseError::UnsupportedLinktype: return "unsupported link type";
        case ParseError::UnsupportedNetworkType: return "unsupported network type";
        case ParseError::UnsupportedTransportType: return "unsupported transport type";
        case ParseError::MalformedHeader: return "malformed header";
        case ParseError::InvalidFieldValue: return "invalid field value";
        case ParseError::ChecksumMismatch: return "checksum mismatch";
        default: return "unknown error";
    }
}

inline std::ostream& operator<<(std::ostream& os, ParseError e) {
    return os << toString(e);
}

}