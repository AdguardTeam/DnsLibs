#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <ag_defs.h>

namespace ag::dnscrypt {

constexpr size_t MAX_DNS_UDP_SAFE_PACKET_SIZE = 1252;
constexpr size_t CLIENT_MAGIC_LEN = 8;
constexpr size_t KEY_SIZE = 32;

using key_array = uint8_array<KEY_SIZE>;
using client_magic_array = uint8_array<CLIENT_MAGIC_LEN>;

/**
 * Crypto construction represents the encryption algorithm
 */
enum class crypto_construction : uint16_t {
    UNDEFINED, /** UNDEFINED is the default value for empty cert_info only */
    X_SALSA_20_POLY_1305 = 0x0001, /** X_SALSA_20_POLY_1305 encryption */
    X_CHACHA_20_POLY_1305 = 0x0002, /** X_CHACHA_20_POLY_1305 encryption */
};

/**
 * Convert crypto construction to string view
 * @param value Crypto construction to convert
 * @return String representation if value holds valid crypto construction, string view with empty string otherwise
 */
std::string_view crypto_construction_str(crypto_construction value);

/**
 * Client protocol
 */
enum class protocol {
    UDP,
    TCP,
};

/**
 * Convert client protocol to string view
 * @param value Client protocol to convert
 * @return String representation if value holds valid client protocol, string view with empty string otherwise
 */
std::string_view protocol_str(protocol value);

} // namespace ag::dnscrypt
