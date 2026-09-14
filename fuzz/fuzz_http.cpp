#include <net/protocols/http.h>

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::vector<uint8_t> buf(data, data + size);
    std::span<const uint8_t> span{buf};

    while (!span.empty()) {
        net::http::Header header{};
        size_t before = span.size();
        if (net::http::parse(span, header) != net::ParseError::None) break;
        (void)header.toString();
        (void)header.toJson();
        if (header.chunked) {
            std::vector<uint8_t> body;
            size_t prefix = 0;
            if (net::http::parseChunkedBody(span, &body, &prefix) != net::ParseError::None) break;
        } else if (header.has_content_length) {
            if (span.size() < header.content_length) break;
            span = span.subspan(static_cast<size_t>(header.content_length));
        }
        if (span.size() >= before) break;
    }

    std::span<const uint8_t> whole{buf};
    std::vector<uint8_t> body;
    size_t prefix = 0;
    (void)net::http::parseChunkedBody(whole, &body, &prefix);
    return 0;
}
