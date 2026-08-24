#include <net/util/string.h>

namespace util {

bool isEquals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

std::string indent(std::string_view str, std::string_view prefix) {
    if (str.empty()) return {};

    std::string out;
    out.reserve(str.size() + prefix.size());

    std::size_t pos = 0;
    while (pos < str.size()) {
        out.append(prefix);
        const std::size_t new_line = str.find('\n', pos);
        if (new_line == std::string_view::npos) {
            out.append(str.data() + pos, str.size() - pos);
            break;
        }
        out.append(str.data() + pos, new_line - pos);
        out.push_back('\n');

        pos = new_line + 1;
    }

    return out;
}

}