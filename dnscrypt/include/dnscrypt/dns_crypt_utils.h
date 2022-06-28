#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include "common/defs.h"
#include "common/net_utils.h"
#include <ldns/ldns.h>

namespace ag::dnscrypt {

constexpr size_t MAX_DNS_UDP_SAFE_PACKET_SIZE = 1252;
constexpr size_t CLIENT_MAGIC_LEN = 8;
constexpr size_t KEY_SIZE = 32;

using KeyArray = Uint8Array<KEY_SIZE>;
using ClientMagicArray = Uint8Array<CLIENT_MAGIC_LEN>;

using ldns_pkt_ptr = UniquePtr<ldns_pkt, &ldns_pkt_free>;
using ldns_buffer_ptr = UniquePtr<ldns_buffer, &ldns_buffer_free>;

/**
 * Crypto construction represents the encryption algorithm
 */
enum class CryptoConstruction : uint16_t {
    UNDEFINED, /** UNDEFINED is the default value for empty cert_info only */
    X_SALSA_20_POLY_1305 = 0x0001, /** X_SALSA_20_POLY_1305 encryption */
    X_CHACHA_20_POLY_1305 = 0x0002, /** X_CHACHA_20_POLY_1305 encryption */
};

} // namespace ag::dnscrypt
