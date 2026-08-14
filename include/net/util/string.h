#pragma once

#include <string_view>
#include <string>

namespace util {

std::string indent(std::string_view s, std::string_view prefix);

}