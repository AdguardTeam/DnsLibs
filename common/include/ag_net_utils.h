#pragma once

#include <chrono>
#include <ctime>
#include <string>
#include <string_view>
#include <ag_defs.h>
#include <ag_socket_address.h>

namespace ag::utils {

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

/**
 * @return a string representation of an IP address, or
 *         an empty string if an error occured or addr is empty
 */
std::string addr_to_str(uint8_view addr);

/**
 * @param address a numeric IP address, with an optional port number
 * @return a socket_address parsed from the address string
 */
socket_address str_to_socket_address(std::string_view address);

} // namespace ag::utils