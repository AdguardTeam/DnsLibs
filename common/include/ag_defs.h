#pragma once

#include <array>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>
#include <ldns/buffer.h>
#include <ldns/packet.h>
#include <ldns/rdata.h>

namespace ag {

// Functor template for zero-storage static deleters in unique_ptr
template<auto func>
using ftor = std::integral_constant<decltype(func), func>;

using opt_string = std::optional<std::string>;
using err_string = opt_string;
using opt_string_view = std::optional<std::string_view>;
using err_string_view = opt_string_view;
using uint8_view = std::basic_string_view<uint8_t>;
using uint8_vector = std::vector<uint8_t>;
template <typename K, typename V>
using hash_map = std::unordered_map<K, V>;
template <typename K>
using hash_set = std::unordered_set<K>;
template<size_t S>
using uint8_array = std::array<uint8_t, S>;

using ldns_buffer_ptr = std::unique_ptr<ldns_buffer, ftor<&ldns_buffer_free>>;
using ldns_pkt_ptr = std::unique_ptr<ldns_pkt, ftor<&ldns_pkt_free>>;
using ldns_rdf_ptr = std::unique_ptr<ldns_rdf, ftor<&ldns_rdf_free>>;
template<typename T>
using allocated_ptr = std::unique_ptr<T, ftor<&std::free>>;

constexpr size_t ipv4_address_size = 4;
constexpr size_t ipv6_address_size = 16;
using ipv4_address_array = uint8_array<ipv4_address_size>;
using ipv6_address_array = uint8_array<ipv6_address_size>;
using ip_address_variant = std::variant<std::monostate, ipv4_address_array, ipv6_address_array>;

// Convenient struct to tie a value and its mutex together
template<typename T, typename Mutex = std::mutex>
struct with_mtx {
    T val;
    Mutex mtx;
};

} // namespace ag
