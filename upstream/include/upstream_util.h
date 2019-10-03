#ifndef AGDNS_UPSTREAM_UPSTREAM_UTIL_H
#define AGDNS_UPSTREAM_UPSTREAM_UTIL_H

#include <string>
#include <optional>
#include <chrono>
#include <time.h>
#include <unordered_map>

namespace ag {

using opt_string = std::optional<std::string>;
using err_string = opt_string;
template <class K, class V>
using hash_map = std::unordered_map<K, V>;

namespace util {

/**
 * Split address string to host and port
 * @param address_string Address string
 * @return Host and port
 */
std::pair<std::string_view, std::string_view> split_host_port(std::string_view address_string);

/**
 * Join host and port into address string
 * @param host Host
 * @param port Port
 * @return Address string
 */
std::string join_host_port(std::string_view host, std::string_view port);

/**
 * Converts duration (microsecond resolution) to timeval structure
 * @param usecs Microseconds
 * @return Timeval with microsecond resolution
 */
timeval duration_to_timeval(std::chrono::microseconds usecs);

} // namespace ag::util

} // namespace ag

#endif //AGDNS_UPSTREAM_UPSTREAM_UTIL_H
