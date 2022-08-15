#include "dns_crypt_padding.h"
#include <sodium.h>

namespace ag::dns::dnscrypt {

bool pad(Uint8Vector &packet, size_t min_size) {
    auto unpadded_buflen = packet.size();
    packet.resize(min_size);
    return 0 == sodium_pad(nullptr, packet.data(), unpadded_buflen, packet.size(), packet.size());
}

bool unpad(Uint8Vector &packet) {
    size_t unpadded_buflen = 0;
    if (0 != sodium_unpad(&unpadded_buflen, packet.data(), packet.size(), packet.size())) {
        return false;
    }
    packet.resize(unpadded_buflen);
    return true;
}

} // namespace ag::dns::dnscrypt
