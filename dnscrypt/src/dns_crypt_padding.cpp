#include <sodium.h>
#include "dns_crypt_padding.h"

ag::err_string ag::dnscrypt::pad(uint8_vector &packet, size_t min_size) {
    auto unpadded_buflen = packet.size();
    packet.resize(min_size);
    if (sodium_pad(nullptr, packet.data(), unpadded_buflen, packet.size(), packet.size()) != 0) {
        return "Can not pad";
    }
    return std::nullopt;
}

ag::err_string ag::dnscrypt::unpad(uint8_vector &packet) {
    size_t unpadded_buflen = 0;
    if (sodium_unpad(&unpadded_buflen, packet.data(), packet.size(), packet.size()) != 0) {
        return "Can not unpad";
    }
    packet.resize(unpadded_buflen);
    return std::nullopt;
}
