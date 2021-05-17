#include <dns_crypt_utils.h>

std::string_view ag::dnscrypt::crypto_construction_str(crypto_construction value) {
    switch (value) {
    case crypto_construction::UNDEFINED:
        return "UNDEFINED";
    case crypto_construction::X_SALSA_20_POLY_1305:
        return "X_SALSA_20_POLY_1305";
    case crypto_construction::X_CHACHA_20_POLY_1305:
        return "X_CHACHA_20_POLY_1305";
    default:
        return "";
    }
}
