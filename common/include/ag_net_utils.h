#pragma once

#include <chrono>
#include <ctime>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <ag_defs.h>
#include <ag_socket_address.h>
#include <event2/event.h>

namespace ag::utils {


#ifndef _WIN32
static constexpr auto AG_ETIMEDOUT = ETIMEDOUT;
static constexpr auto AG_ECONNREFUSED = ECONNREFUSED;
#else
static constexpr auto AG_ETIMEDOUT = WSAETIMEDOUT;
static constexpr auto AG_ECONNREFUSED = WSAECONNREFUSED;
#endif

enum transport_protocol {
    TP_UDP,
    TP_TCP,
};


/**
 * Split address string to host and port with error
 * @param address_string Address string
 * @param require_ipv6_addr_in_square_brackets Require IPv6 address in square brackets
 * @param require_non_empty_port Require non-empty port after colon
 * @return Host, port, error
 */
std::tuple<std::string_view, std::string_view, err_string_view> split_host_port_with_err(
        std::string_view address_string, bool require_ipv6_addr_in_square_brackets = false,
        bool require_non_empty_port = false);

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

/**
 * @param err Socket error
 * @return True if socket error is EAGAIN/EWOULDBLOCK
 */
bool socket_error_is_eagain(int err);

/**
 * Make a socket bound to the specified interface
 * @param fd       socket descriptor
 * @param family   socket family
 * @param if_index interface index
 * @return error string or std::nullopt if successful
 */
err_string bind_socket_to_if(evutil_socket_t fd, int family, uint32_t if_index);

/**
 * Make a socket bound to the specified interface
 * @param fd      socket descriptor
 * @param family  socket family
 * @param if_name interface name
 * @return error string or std::nullopt if successful
 */
err_string bind_socket_to_if(evutil_socket_t fd, int family, const char *if_name);

/**
 * Get the address of the peer connected to the socket
 * @return some address if successful
 */
std::optional<socket_address> get_peer_address(evutil_socket_t fd);

/**
 * Get the current address to which the socket is bound
 * @return some address if successful
 */
std::optional<socket_address> get_local_address(evutil_socket_t fd);

} // namespace ag::utils
