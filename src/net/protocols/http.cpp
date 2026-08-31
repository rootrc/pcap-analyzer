#include <net/protocols/http.h>
#include <net/util/string.h>

#include <cstring>
#include <charconv>
#include <limits>
#include <iomanip>
#include <sstream>

namespace net::http {

namespace {

ParseError readLineCRLF(std::span<const uint8_t>& span, std::string_view& out) {
    std::string_view view(reinterpret_cast<const char*>(span.data()), span.size());
    size_t r = view.find('\r');
    if (r == std::string_view::npos || r + 1 >= view.size()) return ParseError::UnexpectedEof;
    if (view[r + 1] != '\n') return ParseError::MalformedHeader;
    out = view.substr(0, r);
    span = span.subspan(r + 2);
    return ParseError::None;
}

bool isToken(char c) {
    unsigned char u = static_cast<unsigned char>(c);
    if ((u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z') || (u >= '0' && u <= '9')) return true;
    switch (u) {
        case '!': case '#': case '$': case '%': case '&': case '\'':
        case '*': case '+': case '-': case '.': case '^': case '_':
        case '`': case '|': case '~':
            return true;
        default:
            return false;
    }
}

bool isToken(std::string_view s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (!isToken(c)) return false;
    }
    return true;
}

std::string_view trimOws(std::string_view s) {
    size_t l = 0;
    size_t r = s.size();
    while (l < r && (s[l] == ' ' || s[l] == '\t')) l++;
    while (l < r && (s[r - 1] == ' ' || s[r - 1] == '\t')) r--;
    return s.substr(l, r - l);
}

ParseError parseDecimal(std::string_view s, uint64_t& out) {
    if (s.empty()) return ParseError::MalformedHeader;
    constexpr uint64_t limit = std::numeric_limits<uint64_t>::max();
    uint64_t value = 0;
    for (char c : s) {
        if (!std::isdigit(c)) return ParseError::MalformedHeader;
        uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > (limit - digit) / 10) return ParseError::MalformedHeader;
        value = value * 10 + digit;
    }
    out = value;
    return ParseError::None;
}

ParseError parseChunkSize(std::string_view line, uint64_t& out) {
    size_t ext = line.find(';');
    std::string_view digits = line;
    if (ext != std::string_view::npos) digits = line.substr(0, ext);
    while (!digits.empty() && (digits.back() == ' ' || digits.back() == '\t')) digits.remove_suffix(1);
    if (digits.empty()) return ParseError::MalformedHeader;

    const auto result = std::from_chars(digits.data(), digits.data() + digits.size(), out, 16);
    if (result.ec != std::errc{} || result.ptr != digits.data() + digits.size()) {
        return ParseError::MalformedHeader;
    }
    return ParseError::None;
}

ParseError parseStartLine(std::span<const uint8_t>& span, Header& header) {
    std::string_view start_line;
    if (auto err = readLineCRLF(span, start_line); err != ParseError::None) return err;
    if (start_line.empty() || start_line.find('\n') != std::string_view::npos) return ParseError::MalformedHeader;

    size_t space1 = start_line.find(' ');
    if (space1 == std::string_view::npos) return ParseError::MalformedHeader;
    size_t space2 = start_line.find(' ', space1 + 1);

    std::string_view first = start_line.substr(0, space1);
    std::string_view second;
    std::string_view third;
    if (space2 == std::string_view::npos) {
        second = start_line.substr(space1 + 1);
    } else {
        second = start_line.substr(space1 + 1, space2 - space1 - 1);
        third = start_line.substr(space2 + 1);
    }

    if (first.rfind("HTTP/", 0) == 0) {
        if (second.size() != 3 || !std::isdigit(second[0]) || !std::isdigit(second[1]) || !std::isdigit(second[2])) {
            return ParseError::MalformedHeader;
        }
        header.type = MessageType::Response;
        header.version = first;
        header.status_code = static_cast<uint16_t>((second[0] - '0') * 100 + (second[1] - '0') * 10 + (second[2] - '0'));
        header.reason_phrase = third;
    } else {
        if (space2 == std::string_view::npos) return ParseError::MalformedHeader;
        if (!isToken(first) || second.empty()) return ParseError::MalformedHeader;
        header.type = MessageType::Request;
        header.method = first;
        header.target = second;
        header.version = third;
    }

    if (header.version != "HTTP/1.0" && header.version != "HTTP/1.1") {
        return ParseError::UnsupportedVersion;
    }
    return ParseError::None;
}

ParseError parseFields(std::span<const uint8_t>& span, std::vector<Field>* fields) {
    while (true) {
        std::string_view line;
        if (auto err = readLineCRLF(span, line); err != ParseError::None) return err;
        if (line.empty()) return ParseError::None;
        if (line[0] == ' ' || line[0] == '\t') return ParseError::MalformedHeader;

        size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0) return ParseError::MalformedHeader;
        if (line[colon - 1] == ' ' || line[colon - 1] == '\t') return ParseError::MalformedHeader;

        Field field{std::string(line.substr(0, colon)), std::string(trimOws(line.substr(colon + 1)))};
        if (!isToken(field.name)) return ParseError::MalformedHeader;
        if (field.value.find('\n') != std::string_view::npos || field.value.find('\0') != std::string_view::npos) {
            return ParseError::MalformedHeader;
        }
        if (fields) {
            fields->push_back(field);
        }
    }
}

ParseError parseFraming(Header& header) {
    bool saw_transfer_encoding = false;
    bool saw_content_length = false;
    std::vector<std::string_view> encodings;
    std::string_view content_length;
    for (const Field& f : header.fields) {
        if (util::isEquals(f.name, "Transfer-Encoding")) {
            saw_transfer_encoding = true;
            encodings.push_back(trimOws(f.value));
        } else if (util::isEquals(f.name, "Content-Length")) {
            if (!saw_content_length) {
                saw_content_length = true;
                content_length = f.value;
            } else if (f.value != content_length) {
                return ParseError::MalformedHeader;
            }
        }
    }

    if (saw_transfer_encoding && saw_content_length) return ParseError::MalformedHeader;
    if (saw_transfer_encoding) {
        if (!util::isEquals(encodings.back(), "chunked")) {
            return ParseError::MalformedHeader;
        }
        header.chunked = true;
    } else if (saw_content_length) {
        uint64_t value = 0;
        if (auto err = parseDecimal(content_length, value); err != ParseError::None) return err;
        header.has_content_length = true;
        header.content_length = value;
    }

    return ParseError::None;
}

}

ParseError parse(std::span<const uint8_t>& span, Header& header) {
    std::span<const uint8_t> span_copy = span;

    auto fail = [&](ParseError err) {
        span = span_copy;
        return err;
    };

    if (auto err = parseStartLine(span, header); err != ParseError::None) return fail(err);
    if (auto err = parseFields(span, &header.fields); err != ParseError::None) return fail(err);
    if (auto err = parseFraming(header); err != ParseError::None) return fail(err);

    return ParseError::None;
}

ParseError parseChunkedBody(std::span<const uint8_t>& span, std::vector<uint8_t>* out, size_t* complete_prefix) {
    std::span<const uint8_t> span_copy = span;
    size_t out_start = out ? out->size() : 0;
    size_t boundary = 0;

    if (complete_prefix) *complete_prefix = 0;

    auto fail = [&](ParseError err) {
        if (complete_prefix) *complete_prefix = boundary;
        if (out) out->resize(out_start);
        span = span_copy;
        return err;
    };

    while (true) {
        std::string_view size_line;
        if (auto err = readLineCRLF(span, size_line); err != ParseError::None) return fail(err);

        uint64_t chunk_size = 0;
        if (auto err = parseChunkSize(size_line, chunk_size); err != ParseError::None) return fail(err);
        if (chunk_size == 0) break;

        if (span.size() < chunk_size) return fail(ParseError::UnexpectedEof);
        if (out) out->insert(out->end(), span.data(), span.data() + chunk_size);
        span = span.subspan(static_cast<size_t>(chunk_size));

        std::string_view terminator;
        if (auto err = readLineCRLF(span, terminator); err != ParseError::None) return fail(err);
        if (!terminator.empty()) return fail(ParseError::MalformedHeader);

        boundary = span_copy.size() - span.size();
    }

    if (auto err = parseFields(span, nullptr); err != ParseError::None) return fail(err);

    return ParseError::None;
}

const std::string* Header::fieldValue(const std::string& name) const {
    for (const Field& f : fields) {
        if (util::isEquals(f.name, name)) return &f.value;
    }
    return nullptr;
}

bool Header::bodyForbidden() const noexcept {
    return type == MessageType::Response &&
           ((100 <= status_code && status_code < 200) || status_code == 204 || status_code == 304);
}

std::string Header::toString() const noexcept {
    std::ostringstream oss;
    oss << "HTTPHeader {\n";
    if (type == MessageType::Request) {
        oss << "  " << method << " " << target << " " << version << '\n';
    } else if (type == MessageType::Response) {
        oss << "  " << version << " " << status_code << " " << reason_phrase << '\n';
    }
    for (const Field& f : fields) {
        oss << "  " << f.name << ": " << f.value << '\n';
    }
    oss << "}";
    return oss.str();
}

std::string Header::toJson() const noexcept {
    std::ostringstream oss;
    oss << "\"http\": {\n"
        << "  \"type\": ";

    if (type == MessageType::Request) {
        oss << "\"request\",\n"
            << "  \"method\": \"" << method << "\",\n"
            << "  \"target\": \"" << target << "\",\n"
            << "  \"version\": \"" << version << "\",\n";
    } else if (type == MessageType::Response) {
        oss << "\"response\",\n"
            << "  \"version\": \"" << version << "\",\n"
            << "  \"status_code\": " << status_code << ",\n"
            << "  \"reason_phrase\": \"" << reason_phrase << "\",\n";
    }
    oss << "  \"fields\": {\n";
    for (std::size_t i = 0; i < fields.size(); ++i) {
        oss << "    \"" << fields[i].name << "\": \"" << fields[i].value << "\"";
        if (i != fields.size() - 1) {
            oss << ",";
        }
        oss << "\n";
    }
    oss << "  }\n"
        << "}";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const Header& h) {
    return os << h.toString();
}

}