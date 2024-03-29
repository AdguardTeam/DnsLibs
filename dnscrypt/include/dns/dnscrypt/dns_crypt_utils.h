#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include "common/defs.h"
#include "common/net_utils.h"
#include "dns/common/dns_defs.h"
#include <ldns/ldns.h>

namespace ag::dns::dnscrypt {

constexpr size_t MAX_DNS_UDP_SAFE_PACKET_SIZE = 1252;
constexpr size_t CLIENT_MAGIC_LEN = 8;
constexpr size_t KEY_SIZE = 32;

using KeyArray = Uint8Array<KEY_SIZE>;
using ClientMagicArray = Uint8Array<CLIENT_MAGIC_LEN>;

/**
 * Crypto construction represents the encryption algorithm
 */
enum class CryptoConstruction : uint16_t {
    UNDEFINED,                      /** UNDEFINED is the default value for empty cert_info only */
    X_SALSA_20_POLY_1305 = 0x0001,  /** X_SALSA_20_POLY_1305 encryption */
    X_CHACHA_20_POLY_1305 = 0x0002, /** X_CHACHA_20_POLY_1305 encryption */
};

} // namespace ag::dns::dnscrypt
