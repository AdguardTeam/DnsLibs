#pragma once

#include <string_view>
#include <vector>
#include <event2/util.h> // for sockaddr, sockaddr_storage, getaddrinfo, getnameinfo
#ifdef __ANDROID__
#include <netinet/in.h> // not building on android if not included
#endif // __ANDROID__
#include <ag_defs.h>

namespace ag {

/**
 * Socket address (IP address and port)
 */
class socket_address {
public:
    socket_address();

    /**
     * @param numeric_host String containing the IP address
     * @param port         Port number
     */
    socket_address(std::string_view numeric_host, uint16_t port);
    /**
     * @param addr Vector containing IP address bytes. Should be 4 or 16 bytes length
     * @param port Port number
     */
    socket_address(ag::uint8_view addr, uint16_t port);
    /**
     * @param addr C sockaddr struct
     */
    explicit socket_address(const sockaddr* addr);

    bool operator<(const socket_address &other) const;
    bool operator==(const socket_address &other) const;
    bool operator!=(const socket_address &other) const;

    /**
     * @return Pointer to sockaddr_storage structure
     */
    const sockaddr *c_sockaddr() const;

    /**
     * @return sizeof(sockaddr_in) for IPv4 and sizeof(sockaddr_in6) for IPv6
     */
    ev_socklen_t c_socklen() const;

    /**
     * @return IP address bytes
     */
    uint8_view addr() const;

    /**
     * @return If this is an IPv4-mapped address, return the IPv4 address bytes, otherwise, same as `addr()`
     */
    uint8_view addr_unmapped() const;

    /**
     * @return IP address variant
     */
    ip_address_variant addr_variant() const;

    /**
     * @return Port number
     */
    uint16_t port() const;

    /**
     * @return String containing IP address
     */
    std::string host_str() const;

    /**
     * @return String containing IP address and port
     */
    std::string str() const;

    /**
     * @return True if IP is valid (AF_INET or AF_INET6)
     */
    bool valid() const;

    /**
     * @return True if address family is AF_INET or address is IPv4 mapped
     */
    bool is_ipv4() const;

    /**
     * @return True if address is IPv4 mapped
     */
    bool is_ipv4_mapped() const;

    /**
     * @return True if address family is AF_INET6
     */
    bool is_ipv6() const;

    /**
     * Cast address to target address family.
     * IPv4 addresses are mapped/unmapped automatically.
     * If address cannot be cast, return invalid address
     * @param family Target address family
     * @return Address of target address family
     */
    socket_address socket_family_cast(int family) const;

private:
    /** sockaddr_storage structure. Internally this is just sockaddr_storage wrapper */
    sockaddr_storage m_ss;

    ag::socket_address to_ipv4_unmapped() const;
    ag::socket_address to_ipv4_mapped() const;
};

} // namespace ag

namespace std {
template<>
struct hash<ag::socket_address> {
    size_t operator()(const ag::socket_address &address) const {
        std::string_view bytes = {(const char *) address.c_sockaddr(), (size_t) address.c_socklen()};
        return std::hash<std::string_view>{}(bytes);
    }
};
} // namespace std
