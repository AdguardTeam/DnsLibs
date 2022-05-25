#include "dns_crypt_padding.h"
#include <sodium.h>

namespace ag::dnscrypt {

ErrString pad(Uint8Vector &packet, size_t min_size) {
    auto unpadded_buflen = packet.size();
    packet.resize(min_size);
    if (sodium_pad(nullptr, packet.data(), unpadded_buflen, packet.size(), packet.size()) != 0) {
        return "Can not pad";
    }
    return std::nullopt;
}

ErrString unpad(Uint8Vector &packet) {
    size_t unpadded_buflen = 0;
    if (sodium_unpad(&unpadded_buflen, packet.data(), packet.size(), packet.size()) != 0) {
        return "Can not unpad";
    }
    packet.resize(unpadded_buflen);
    return std::nullopt;
}

} // namespace ag::dnscrypt
