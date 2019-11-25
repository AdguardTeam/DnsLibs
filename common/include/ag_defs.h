#pragma once

#include <memory>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <ldns/buffer.h>
#include <ldns/packet.h>
#include <ldns/rdata.h>
#include <mutex>

namespace ag {

using opt_string = std::optional<std::string>;
using err_string = opt_string;
template <typename K, typename V>
using hash_map = std::unordered_map<K, V>;
template <typename K>
using hash_set = std::unordered_set<K>;
using uint8_view = std::basic_string_view<uint8_t>;
using uint8_vector = std::vector<uint8_t>;
template<size_t S>
using uint8_array = std::array<uint8_t, S>;

// Functor template for zero-storage static deleters in unique_ptr
template<auto func>
struct ftor
{
    template<typename... Ts>
    inline auto operator()(Ts&&... ts) const
    {
        return func(std::forward<Ts...>(ts...));
    }
};

template<typename T>
using allocated_ptr = std::unique_ptr<T, ftor<&std::free>>;
using ldns_buffer_ptr = std::unique_ptr<ldns_buffer, ftor<&ldns_buffer_free>>;
using ldns_pkt_ptr = std::unique_ptr<ldns_pkt, ftor<&ldns_pkt_free>>;
using ldns_rdf_ptr = std::unique_ptr<ldns_rdf, ftor<&ldns_rdf_free>>;


// Convenient struct to tie a value and its mutex together
template<typename T, typename Mutex = std::mutex>
struct with_mtx {
    T val;
    Mutex mtx;
};

} // namespace ag
