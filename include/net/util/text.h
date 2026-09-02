#pragma once

#include <cstdint>
#include <ostream>
#include <string_view>
#include <string>

namespace util {

bool isEquals(std::string_view a, std::string_view b);
std::string indent(std::string_view s, std::string_view prefix);

void printDuration(std::ostream& os, uint64_t ns);
void printBytes(std::ostream& os, uint64_t bytes);
void printRate(std::ostream& os, double bps);

}
