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
    outbound_proxy_protocol protocol; // The proxy protocol
    std::string address; // The proxy server address (must be a valid IP address)
    uint16_t port; // The proxy server port
    std::optional<outbound_proxy_auth_info> auth_info; // The authentication information
    bool trust_any_certificate; // If true and the proxy connection is secure, the certificate won't be verified
};

}
