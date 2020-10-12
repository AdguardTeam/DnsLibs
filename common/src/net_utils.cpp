#include <ag_utils.h>
#include <ag_net_utils.h>
#include <ag_socket_address.h>
#include <event2/util.h>

#ifndef _WIN32
#include <net/if.h> // For if_nametoindex/if_indextoname
#else
#include <Iphlpapi.h>
#include <Winsock2.h>
#include <Ws2tcpip.h>
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
#endif

std::tuple<std::string_view, std::string_view, ag::err_string_view> ag::utils::split_host_port_with_err(
        std::string_view address_string, bool require_ipv6_addr_in_square_brackets, bool require_non_empty_port) {
    if (!address_string.empty() && address_string.front() == '[') {
        auto pos = address_string.find("]:");
        if (pos != std::string_view::npos) {
            auto port = address_string.substr(pos + 2);
            return {address_string.substr(1, pos - 1), port,
                    (require_non_empty_port && port.empty())
                    ? err_string_view("Port after colon is empty in IPv6 address")
                    : std::nullopt};
        } else if (address_string.back() == ']') {
            return {address_string.substr(1, address_string.size() - 2), {}, std::nullopt};
        } else {
            return {address_string, {}, "IPv6 address contains `[` but not contains `]`"};
        }
    } else {
        auto pos = address_string.find(':');
        if (pos != std::string_view::npos) {
            auto rpos = address_string.rfind(':');
            if (pos != rpos) { // This is an IPv6 address without a port
                return {address_string, {},
                        require_ipv6_addr_in_square_brackets
                        ? err_string_view("IPv6 address not in square brackets")
                        : std::nullopt};
            }
            auto port = address_string.substr(pos + 1);
            return {address_string.substr(0, pos), port,
                    (require_non_empty_port && port.empty())
                    ? err_string_view("Port after colon is empty in IPv4 address")
                    : std::nullopt};
        }
    }
    return {address_string, {}, std::nullopt};
}

std::pair<std::string_view, std::string_view> ag::utils::split_host_port(std::string_view address_string) {
    auto[host, port, err] = split_host_port_with_err(address_string);
    return {host, port};
}

std::string ag::utils::join_host_port(std::string_view host, std::string_view port) {
    if (host.find(':') != std::string_view::npos) {
        std::string result = "[";
        result += host;
        result += "]:";
        result += port;
        return result;
    }
    std::string result{host};
    result += ":";
    result += port;
    return result;
}

timeval ag::utils::duration_to_timeval(std::chrono::microseconds usecs) {
    static constexpr intmax_t denom = decltype(usecs)::period::den;
    return {
        .tv_sec = static_cast<decltype(timeval::tv_sec)>(usecs.count() / denom),
        .tv_usec = static_cast<decltype(timeval::tv_usec)>(usecs.count() % denom)
    };
}

std::string ag::utils::addr_to_str(uint8_view v) {
    char p[INET6_ADDRSTRLEN];
    if (v.size() == ipv4_address_size) {
        if (evutil_inet_ntop(AF_INET, v.data(), p, sizeof(p))) {
            return p;
        }
    } else if (v.size() == ipv6_address_size) {
        if (evutil_inet_ntop(AF_INET6, v.data(), p, sizeof(p))) {
            return p;
        }
    }
    return {};
}

ag::socket_address ag::utils::str_to_socket_address(std::string_view address) {
    auto [host, port_view] = ag::utils::split_host_port(address);

    if (port_view.empty()) {
        return socket_address{host, 0};
    }

    std::string port_str{port_view};
    char *end = nullptr;
    auto port = std::strtoll(port_str.c_str(), &end, 10);

    if (end != &port_str.back() + 1 || port < 0 || port > UINT16_MAX) {
        return {};
    }

    return socket_address{host, (uint16_t) port};
}

bool ag::utils::socket_error_is_eagain(int err) {
#ifndef _WIN32
    return err == EAGAIN || err == EWOULDBLOCK;
#else
    return err == WSAEWOULDBLOCK;
#endif
}

ag::err_string ag::utils::bind_socket_to_if(evutil_socket_t fd, int family, uint32_t if_index) {
#if defined(__linux__)
    char buf[IF_NAMESIZE];
    const char *name = if_indextoname(if_index, buf);
    if (!name) {
        return AG_FMT("{}: {}", errno, strerror(errno));
    }
    return bind_socket_to_if(fd, family, name);
#else
#if defined(_WIN32)
    constexpr int ipv4_opt = IP_UNICAST_IF;
    constexpr int ipv6_opt = IPV6_UNICAST_IF;
#else
    constexpr int ipv4_opt = IP_BOUND_IF;
    constexpr int ipv6_opt = IPV6_BOUND_IF;
#endif
    int option;
    int level;
    switch (family) {
    case AF_INET:
        level = IPPROTO_IP;
        option = ipv4_opt;
        break;
    case AF_INET6:
        level = IPPROTO_IPV6;
        option = ipv6_opt;
        break;
    default:
        return AG_FMT("Unsuppported socket family: {}", family);
    }
    int ret = setsockopt(fd, level, option, (char *) &if_index, sizeof(if_index)); // Cast to (char *) for Windows
    if (ret != 0) {
        int error = evutil_socket_geterror(fd);
        return AG_FMT("{}: {}", error, evutil_socket_error_to_string(error));
    }
    return {};
#endif
}

ag::err_string ag::utils::bind_socket_to_if(evutil_socket_t fd, int family, const char *if_name) {
#if defined(__linux__)
    (void)family;
    int ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name));
    if (ret != 0) {
        return AG_FMT("{}: {}", errno, strerror(errno));
    }
    return {};
#else
    uint32_t if_index = if_nametoindex(if_name);
    if (if_index == 0) {
        return AG_FMT("Invalid interface name: {}", if_name);
    }
    return bind_socket_to_if(fd, family, if_index);
#endif
}
