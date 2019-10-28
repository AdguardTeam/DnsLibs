#pragma once

#include <string_view>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <stdint.h>

namespace ag {

using opt_string = std::optional<std::string>;
using err_string = opt_string;
template <class K, class V>
using hash_map = std::unordered_map<K, V>;
template <class K>
using hash_set = std::unordered_set<K>;
using uint8_view_t = std::basic_string_view<uint8_t>;

}
