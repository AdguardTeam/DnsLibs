#pragma once


#include <string>
#include <optional>
#include <cstdint>


namespace ag {

enum class outbound_proxy_protocol {
    HTTP_CONNECT, // Plain HTTP proxy
    HTTPS_CONNECT, // HTTPs proxy
    SOCKS4, // Socks4 proxy
    SOCKS5, // Socks5 proxy without UDP support
    SOCKS5_UDP, // Socks5 proxy with UDP support
};

struct outbound_proxy_auth_info {
    std::string username;
    std::string password;
};

struct outbound_proxy_settings {
    /// The proxy protocol
    outbound_proxy_protocol protocol;
    /// The proxy server address (must be a valid IP address)
    std::string address;
    /// The proxy server port
    uint16_t port;
    /// The authentication information
    std::optional<outbound_proxy_auth_info> auth_info;
    /// If true and the proxy connection is secure, the certificate won't be verified
    bool trust_any_certificate;
    /// Whether the DNS proxy should ignore the outbound proxy and route quries directly
    /// to target hosts even if it's determined as unavailable
    bool ignore_if_unavailable;
};

}
