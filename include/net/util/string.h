#pragma once

#include <string_view>
#include <string>

namespace util {

bool isEquals(std::string_view a, std::string_view b);
std::string indent(std::string_view s, std::string_view prefix);

}