#pragma once

#include <cstddef>
#include <cstdint>
#include "common/defs.h"
#include "dns_crypt_utils.h"

namespace ag::dns::dnscrypt {

constexpr size_t MAX_DNS_PACKET_SIZE = 4096;
constexpr size_t NONCE_SIZE = 24;
constexpr size_t TAG_SIZE = 16;
constexpr size_t HALF_NONCE_SIZE = NONCE_SIZE / 2;
constexpr size_t PUBLIC_KEY_SIZE = KEY_SIZE;
constexpr size_t QUERY_OVERHEAD = CLIENT_MAGIC_LEN + PUBLIC_KEY_SIZE + HALF_NONCE_SIZE + TAG_SIZE;

using nonce_array = ag::Uint8Array<NONCE_SIZE>;

} // namespace ag::dns::dnscrypt
