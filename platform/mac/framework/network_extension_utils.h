#pragma once

#import <Foundation/Foundation.h>
#import <Network/Network.h>
#import <NetworkExtension/NetworkExtension.h>

#include <arpa/inet.h>
#import <common/net_utils.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * @brief Helpers for working with Apple NetworkExtension App Proxy flows.
 *
 * This header provides small utilities used by the NetworkExtension-based DNS proxy
 * implementation on Apple platforms.
 */
namespace ag::ne_utils {

/**
 * @brief Convert a `NWEndpoint` (host endpoint) to a `sockaddr_storage`.
 *
 * This function expects `NWHostEndpoint` and parses its hostname as a numeric
 * IPv4/IPv6 literal using `inet_pton`.
 *
 * @param endpoint Source endpoint.
 * @param family_hint Address family hint (`AF_INET`, `AF_INET6`, or `AF_UNSPEC`).
 * @param allow_port_zero Whether port 0 is allowed (useful for local bind addresses).
 * @param out_addr Output sockaddr.
 * @param out_len Output sockaddr length.
 * @return `true` if conversion succeeded.
 */
inline bool sockaddr_from_nwendpoint(NWEndpoint *endpoint,
                                    int family_hint,
                                    bool allow_port_zero,
                                    sockaddr_storage *out_addr,
                                    socklen_t *out_len) {
    if (!endpoint || !out_addr || !out_len) {
        return false;
    }
    memset(out_addr, 0, sizeof(*out_addr));
    *out_len = 0;

    if (![endpoint isKindOfClass:NWHostEndpoint.class]) {
        return false;
    }

    NWHostEndpoint *hostEndpoint = (NWHostEndpoint *) endpoint;
    NSString *host = hostEndpoint.hostname;
    NSString *port = hostEndpoint.port;
    if (host.length == 0 || port.length == 0) {
        return false;
    }

    int port_value = port.intValue;
    if (port_value < 0 || port_value > 65535) {
        return false;
    }
    if (!allow_port_zero && port_value == 0) {
        return false;
    }

    const char *host_c = host.UTF8String;
    if (!host_c) {
        return false;
    }

    sockaddr_in sin = {};
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t) port_value);

    sockaddr_in6 sin6 = {};
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons((uint16_t) port_value);

    int v4_ok = inet_pton(AF_INET, host_c, &sin.sin_addr);
    int v6_ok = inet_pton(AF_INET6, host_c, &sin6.sin6_addr);

    if (family_hint == AF_INET) {
        if (v4_ok == 1) {
            memcpy(out_addr, &sin, sizeof(sin));
            *out_len = sizeof(sin);
            return true;
        }
        return false;
    }
    if (family_hint == AF_INET6) {
        if (v6_ok == 1) {
            memcpy(out_addr, &sin6, sizeof(sin6));
            *out_len = sizeof(sin6);
            return true;
        }
        return false;
    }

    if (v6_ok == 1) {
        memcpy(out_addr, &sin6, sizeof(sin6));
        *out_len = sizeof(sin6);
        return true;
    }
    if (v4_ok == 1) {
        memcpy(out_addr, &sin, sizeof(sin));
        *out_len = sizeof(sin);
        return true;
    }

    return false;
}

/**
 * @brief Convert a `sockaddr` to an `NWEndpoint`.
 *
 * The resulting endpoint is an `NWHostEndpoint` with a numeric hostname.
 *
 * @param addr Source address.
 * @param addr_len Length of `addr`.
 * @return New endpoint instance or `nil` on error.
 */
inline NWEndpoint *nwendpoint_from_sockaddr(const sockaddr *addr, socklen_t addr_len) {
    if (!addr || addr_len == 0) {
        return nil;
    }

    char host_buf[INET6_ADDRSTRLEN] = {0};
    NSString *host = nil;
    NSString *port = nil;

    if (addr->sa_family == AF_INET && addr_len >= sizeof(sockaddr_in)) {
        const sockaddr_in *sin = (const sockaddr_in *) addr;
        if (!inet_ntop(AF_INET, &sin->sin_addr, host_buf, sizeof(host_buf))) {
            return nil;
        }
        host = [NSString stringWithUTF8String:host_buf];
        port = [NSString stringWithFormat:@"%u", ntohs(sin->sin_port)];
    } else if (addr->sa_family == AF_INET6 && addr_len >= sizeof(sockaddr_in6)) {
        const sockaddr_in6 *sin6 = (const sockaddr_in6 *) addr;
        if (!inet_ntop(AF_INET6, &sin6->sin6_addr, host_buf, sizeof(host_buf))) {
            return nil;
        }
        host = [NSString stringWithUTF8String:host_buf];
        port = [NSString stringWithFormat:@"%u", ntohs(sin6->sin6_port)];
    } else {
        return nil;
    }

    if (host.length == 0 || port.length == 0) {
        return nil;
    }

    return [NWHostEndpoint endpointWithHostname:host port:port];
}

/**
 * @brief Extract the local address (IP/port) to bind for a UDP app proxy flow.
 *
 * The address is taken from `flow.localEndpoint` and converted via
 * `sockaddr_from_nwendpoint` with port 0 allowed.
 *
 * @param flow Source UDP flow.
 * @param address Output sockaddr.
 * @param address_len Output sockaddr length.
 * @return `true` if the local endpoint was present and conversion succeeded.
 */
inline bool get_flow_local_address(NEAppProxyUDPFlow *flow, sockaddr_storage *address, socklen_t *address_len) {
    if (!flow || !address || !address_len) {
        return false;
    }
    *address_len = 0;
    memset(address, 0, sizeof(*address));
    return sockaddr_from_nwendpoint(flow.localEndpoint, AF_UNSPEC, true, address, address_len);
}

/**
 * @brief Create a nonblocking socket.
 *
 * @param family Address family.
 * @param type Socket type.
 * @param protocol Protocol.
 * @return File descriptor or `-1` on failure.
 */
inline int make_nonblocking_socket(int family, int type, int protocol) {
    int fd = socket(family, type, protocol);
    if (fd < 0) {
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/**
 * @brief Bind socket's outbound interface.
 *
 * Uses `IP_BOUND_IF` / `IPV6_BOUND_IF` to force traffic to go through the
 * provided `nw_interface_t`.
 *
 * @param fd Socket file descriptor.
 * @param interface Network framework interface object.
 * @return `true` if the socket option was applied or no interface was provided.
 */
inline bool set_outbound_interface(int fd, int family, nw_interface_t iface) {
    if (fd < 0) {
        return false;
    }
    if (iface == nullptr) {
        return true;
    }

    uint32_t if_index = nw_interface_get_index(iface);
    if (if_index == 0) {
        return false;
    }

    auto err = ag::utils::bind_socket_to_if(fd, family, if_index);
    return err == nullptr;
}

} // namespace ag::ne_utils
