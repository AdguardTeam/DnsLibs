#include <cstring>
#include <string>
#include <ag_net_utils.h>
#include <ag_socket_address.h>
#include <ag_utils.h>
#ifdef _WIN32
#include <ws2tcpip.h>
#endif

static constexpr uint8_t IPV4_MAPPED_PREFIX[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

static size_t c_socklen(const sockaddr *addr) {
    return addr->sa_family == AF_INET6 ? sizeof(sockaddr_in6) :
           addr->sa_family == AF_INET ? sizeof(sockaddr_in) :
           0;
}

bool ag::socket_address::operator<(const ag::socket_address &other) const {
    return std::memcmp(&m_ss, &other.m_ss, c_socklen()) < 0;
}

bool ag::socket_address::operator==(const ag::socket_address &other) const {
    return std::memcmp(&m_ss, &other.m_ss, c_socklen()) == 0;
}

bool ag::socket_address::operator!=(const ag::socket_address &other) const {
    return !operator==(other);
}

const sockaddr *ag::socket_address::c_sockaddr() const {
    return reinterpret_cast<const sockaddr *>(&m_ss);
}

ev_socklen_t ag::socket_address::c_socklen() const {
    return ::c_socklen((const sockaddr *) &m_ss);
}

ag::socket_address::socket_address()
        : m_ss{} {
}

ag::socket_address::socket_address(const sockaddr *addr)
        : m_ss{} {

    if (addr) {
        std::memcpy(&m_ss, addr, ::c_socklen(addr));
    }
}

static sockaddr_storage make_sockaddr_storage(ag::uint8_view addr, uint16_t port) {
    sockaddr_storage ss{};
    if (addr.size() == 16) {
        auto *sin6 = (sockaddr_in6 *) &ss;
#ifdef SIN6_LEN // Platform with sin*_lens should have this macro
        sin6->sin6_len = sizeof(sockaddr_in6);
#endif // SIN6_LEN
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        std::memcpy(&sin6->sin6_addr, addr.data(), addr.size());
    } else if (addr.size() == 4) {
        auto *sin = (sockaddr_in *) &ss;
#ifdef SIN6_LEN // Platform with sin*_lens should have this macro
        sin->sin_len = sizeof(sockaddr_in);
#endif // SIN6_LEN
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        std::memcpy(&sin->sin_addr, addr.data(), addr.size());
    }
    return ss;
}

static sockaddr_storage make_sockaddr_storage(std::string_view numeric_host, uint16_t port) {
    char p[INET6_ADDRSTRLEN];
    if (numeric_host.size() > sizeof(p) - 1) {
        return {};
    }
    memcpy(p, numeric_host.data(), numeric_host.size());
    p[numeric_host.size()] = '\0';

    ag::ipv6_address_array ip;
    if (1 == evutil_inet_pton(AF_INET, p, ip.data())) {
        return make_sockaddr_storage({ip.data(), ag::ipv4_address_size}, port);
    } else if (1 == evutil_inet_pton(AF_INET6, p, ip.data())) {
        return make_sockaddr_storage({ip.data(), ag::ipv6_address_size}, port);
    }

    return {};
}

ag::socket_address::socket_address(std::string_view numeric_host, uint16_t port)
        : m_ss{make_sockaddr_storage(numeric_host, port)} {
}

ag::socket_address::socket_address(ag::uint8_view addr, uint16_t port)
        : m_ss{make_sockaddr_storage(addr, port)} {
}

ag::uint8_view ag::socket_address::addr() const {
    switch (m_ss.ss_family) {
    case AF_INET: {
        auto &sin = (const sockaddr_in &) m_ss;
        return {(uint8_t *) &sin.sin_addr, ipv4_address_size};
    }
    case AF_INET6: {
        auto &sin6 = (const sockaddr_in6 &) m_ss;
        return {(uint8_t *) &sin6.sin6_addr, ipv6_address_size};
    }
    default:
        return {};
    }
}

ag::ip_address_variant ag::socket_address::addr_variant() const {
    switch (m_ss.ss_family) {
    case AF_INET: {
        auto &sin = (const sockaddr_in &)m_ss;
        return utils::to_array<ipv4_address_size>((const uint8_t *)&sin.sin_addr);
    }
    case AF_INET6: {
        auto &sin6 = (const sockaddr_in6 &)m_ss;
        return utils::to_array<ipv6_address_size>((const uint8_t *)&sin6.sin6_addr);
    }
    default:
        return std::monostate{};
    }
}

uint16_t ag::socket_address::port() const {
    switch (m_ss.ss_family) {
        case AF_INET6:
            return ntohs(((const sockaddr_in6 &) m_ss).sin6_port);
        case AF_INET:
            return ntohs(((const sockaddr_in &) m_ss).sin_port);
        default:
            return 0;
    }
}

std::string ag::socket_address::str() const {
    char host[INET6_ADDRSTRLEN] = "";
    char port[6] = "0";
    getnameinfo(c_sockaddr(), c_socklen(), host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    if (m_ss.ss_family == AF_INET6) {
        return "[" + std::string(host) + "]:" + port;
    } else {
        return host + std::string(":") + port;
    }
}

bool ag::socket_address::valid() const {
    return m_ss.ss_family != AF_UNSPEC;
}

bool ag::socket_address::is_ipv6() const {
    return m_ss.ss_family == AF_INET6;
}

bool ag::socket_address::is_ipv4() const {
    return m_ss.ss_family == AF_INET || is_ipv4_mapped();
}

bool ag::socket_address::is_ipv4_mapped() const {
    return m_ss.ss_family == AF_INET6
           && !memcmp(&((sockaddr_in6 *) &m_ss)->sin6_addr, IPV4_MAPPED_PREFIX, sizeof(IPV4_MAPPED_PREFIX));
}

ag::socket_address ag::socket_address::to_ipv4_unmapped() const {
    if (m_ss.ss_family == AF_INET) {
        return *this;
    }
    if (!is_ipv4_mapped()) {
        return {};
    }
    uint8_view v4 = addr();
    v4.remove_prefix(sizeof(IPV4_MAPPED_PREFIX));
    return {v4, port()};
}

ag::socket_address ag::socket_address::to_ipv4_mapped() const {
    if (m_ss.ss_family == AF_INET6) {
        return *this;
    }
    if (m_ss.ss_family != AF_INET) {
        return {};
    }
    uint8_t mapped[sizeof(in6_addr)];
    memcpy(mapped, IPV4_MAPPED_PREFIX, sizeof(IPV4_MAPPED_PREFIX));
    uint8_view v4 = addr();
    memcpy(mapped + sizeof(IPV4_MAPPED_PREFIX), v4.data(), v4.size());
    return ag::socket_address({mapped, sizeof(mapped)}, port());
}

ag::socket_address ag::socket_address::socket_family_cast(int family) const {
    if (family == AF_INET) {
        return to_ipv4_unmapped();
    } else if (family == AF_INET6) {
        return to_ipv4_mapped();
    } else {
        return {};
    }
}
