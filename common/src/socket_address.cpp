#include <cstring>
#include <string>
#include <ag_net_utils.h>
#include <ag_socket_address.h>
#include <ag_utils.h>
#ifdef _WIN32
#include <ws2tcpip.h>
#endif

bool ag::socket_address::operator<(const ag::socket_address &other) const {
    return std::memcmp(&m_ss, &other.m_ss, c_socklen()) < 0;
}

bool ag::socket_address::operator==(const ag::socket_address &other) const {
    return std::memcmp(&m_ss, &other.m_ss, c_socklen()) == 0;
}

const sockaddr *ag::socket_address::c_sockaddr() const {
    return reinterpret_cast<const sockaddr *>(&m_ss);
}

ev_socklen_t ag::socket_address::c_socklen() const {
    return m_ss.ss_family == AF_INET6 ? sizeof(sockaddr_in6) :
           m_ss.ss_family == AF_INET ? sizeof(sockaddr_in) :
           0;
}

ag::socket_address::socket_address()
        : m_ss{} {
}

ag::socket_address::socket_address(std::string_view address_string)
        : m_ss{} {

    addrinfo *addrinfo_res = nullptr;
    addrinfo addrinfo_hints{};
    addrinfo_hints.ai_family = AF_UNSPEC;
    addrinfo_hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    auto[host, port] = ag::utils::split_host_port(address_string);
    auto getaddrinfo_result = getaddrinfo(std::string(host).c_str(), port.empty() ? nullptr : std::string(port).c_str(),
                                          &addrinfo_hints, &addrinfo_res);

    if (getaddrinfo_result == 0 && addrinfo_res != nullptr) {
        memcpy(&m_ss, addrinfo_res->ai_addr, addrinfo_res->ai_addrlen);
    }

    if (addrinfo_res != nullptr) {
        freeaddrinfo(addrinfo_res);
    }
}

std::vector<uint8_t> ag::socket_address::addr() const {
    switch (m_ss.ss_family) {
        case AF_INET6: {
            auto &sin6 = (const sockaddr_in6 &) m_ss;
            return {(uint8_t *) &sin6.sin6_addr,
                    (uint8_t *) &sin6.sin6_addr + sizeof(sin6.sin6_addr)};
        }
        case AF_INET: {
            auto &sin = (const sockaddr_in &) m_ss;
            return {(uint8_t *) &sin.sin_addr,
                    (uint8_t *) &sin.sin_addr + sizeof(sin.sin_addr)};
        }
        default:
            return {};
    }
}

ag::ip_address_variant ag::socket_address::addr_variant() const {
    static constexpr auto ipv4_size = std::tuple_size<ipv4_address_array>::value;
    static constexpr auto ipv6_size = std::tuple_size<ipv6_address_array>::value;
    auto bytes = addr();
    switch (bytes.size()) {
    case ipv4_size:
        return utils::to_array<ipv4_size>(bytes.data());
    case ipv6_size:
        return utils::to_array<ipv6_size>(bytes.data());
    default:
        return std::monostate{};
    }
}

int ag::socket_address::port() const {
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
    char host[INET6_ADDRSTRLEN + 1] = "unknown";
    char port[6] = "0";
    getnameinfo(c_sockaddr(), c_socklen(), host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    if (m_ss.ss_family == AF_INET6) {
        return "[" + std::string(host) + "]:" + port;
    } else {
        return host + std::string(":") + port;
    }
}

ag::socket_address::socket_address(ag::uint8_view addr, int port)
        : m_ss{} {
    if (addr.size() == 16) {
        auto &sin6 = (sockaddr_in6 &) m_ss;
#ifdef SIN6_LEN // Platform with sin*_lens should have this macro
        sin6.sin6_len = sizeof(sockaddr_in6);
#endif // SIN6_LEN
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons(port);
        std::memcpy(&sin6.sin6_addr, addr.data(), addr.size());
    } else if (addr.size() == 4) {
        auto &sin = (sockaddr_in &) m_ss;
#ifdef SIN6_LEN // Platform with sin*_lens should have this macro
        sin.sin_len = sizeof(sockaddr_in);
#endif // SIN6_LEN
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        std::memcpy(&sin.sin_addr, addr.data(), addr.size());
    }
}

bool ag::socket_address::valid() const {
    return m_ss.ss_family != AF_UNSPEC;
}
