#pragma once


#include <cstdint>
#include <optional>
#include <string>


namespace ag::dns {

enum class OutboundProxyProtocol {
    HTTP_CONNECT, // Plain HTTP proxy
    HTTPS_CONNECT, // HTTPs proxy
    SOCKS4, // Socks4 proxy
    SOCKS5, // Socks5 proxy without UDP support
    SOCKS5_UDP, // Socks5 proxy with UDP support
};

struct OutboundProxyAuthInfo {
    std::string username;
    std::string password;
};

struct OutboundProxySettings {
    /// The proxy protocol
    OutboundProxyProtocol protocol;
    /// The proxy server address or hostname
    std::string address;
    /// The proxy server port
    uint16_t port;
    /**
     * List of the DNS server URLs to be used to resolve a hostname in the proxy server address.
     * The URLs MUST contain the resolved server addresses, not hostnames.
     * E.g. `https://94.140.14.14` is correct, while `dns.adguard.com:53` is not.
     * MUST NOT be empty in case the `address` is a hostname.
     */
    std::vector<std::string> bootstrap;
    /// The authentication information
    std::optional<OutboundProxyAuthInfo> auth_info;
    /// If true and the proxy connection is secure, the certificate won't be verified
    bool trust_any_certificate;
    /// Whether the DNS proxy should ignore the outbound proxy and route queries directly
    /// to target hosts even if it's determined as unavailable
    bool ignore_if_unavailable;
};

} // namespace ag::dns
