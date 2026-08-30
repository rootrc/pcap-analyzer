#pragma once

#include <net/util/endian.h>
#include <net/util/parse_error.h>

#include <span>
#include <string>
#include <vector>

// https://datatracker.ietf.org/doc/html/rfc9110
// https://datatracker.ietf.org/doc/html/rfc9112

namespace net::http {
    constexpr uint16_t PORT = 80;

    enum class MessageType { Unknown, Request, Response };

    struct Field {
        std::string name;
        std::string value;
    };

    struct Header {
        MessageType type = MessageType::Unknown;

        std::string method;
        std::string target;
        std::string version;
        uint16_t status_code = 0;
        std::string reason_phrase;

        std::vector<Field> fields;

        bool has_content_length = false;
        uint64_t content_length = 0;
        bool chunked = false;

        bool isRequest() const noexcept { return type == MessageType::Request; }
        bool isResponse() const noexcept { return type == MessageType::Response; }
        const std::string* fieldValue(const std::string& name) const;
        bool bodyForbidden() const noexcept;

        std::string toString() const noexcept;
        std::string toJson() const noexcept;
    };

    ParseError parse(std::span<const uint8_t>& span, Header& header);
    ParseError parseChunkedBody(std::span<const uint8_t>& span, std::vector<uint8_t>* out = nullptr, size_t* complete_prefix = nullptr);

    std::ostream& operator<<(std::ostream& os, const Header& h);
}