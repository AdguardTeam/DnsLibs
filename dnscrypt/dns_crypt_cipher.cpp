#include <sodium.h>
#include <utility>

#include "common/utils.h"
#include "dns/dnscrypt/dns_crypt_cipher.h"

static constexpr uint8_t ZEROS[16]{};

namespace ag::dns::dnscrypt {

static const struct EnsureSodiumInit {
    EnsureSodiumInit() noexcept {
        int result = ::sodium_init();
        assert(result == 0); // `0` means `initialized for the first time`
    }
} g_ensure_sodium_init [[maybe_unused]];

class XSalsa20Poly1305 : public Cipher {
public:
    [[nodiscard]] SharedKeyResult shared_key(const KeyArray &secret_key, const KeyArray &public_key) const override;
    [[nodiscard]] SealResult seal(Uint8View message, const nonce_array &nonce, const KeyArray &key) const override;
    [[nodiscard]] OpenResult open(Uint8View ciphertext, const nonce_array &nonce, const KeyArray &key) const override;
};

XSalsa20Poly1305::SharedKeyResult XSalsa20Poly1305::shared_key(
        const KeyArray &secret_key, const KeyArray &public_key) const {

    KeyArray shared_key{};
    if (crypto_scalarmult(shared_key.data(), secret_key.data(), public_key.data()) != 0) {
        return make_error(CipherError::AE_SCALARMULT_ERROR);
    }
    if (crypto_core_hsalsa20(shared_key.data(), ZEROS, shared_key.data(), nullptr) != 0) {
        return make_error(CipherError::AE_HSALSA20_ERROR);
    }
    return shared_key;
}

XSalsa20Poly1305::SealResult XSalsa20Poly1305::seal(
        Uint8View message, const nonce_array &nonce, const KeyArray &key) const {

    Uint8Vector ciphertext(message.size() + crypto_secretbox_MACBYTES);
    if (crypto_secretbox_easy(ciphertext.data(), message.data(), message.size(), nonce.data(), key.data()) == 0) {
        return ciphertext;
    }
    return make_error(CipherError::AE_AEAD_SEAL_ERROR, "x_salsa_20_poly_1305 seal");
}

XSalsa20Poly1305::OpenResult XSalsa20Poly1305::open(
        Uint8View ciphertext, const nonce_array &nonce, const KeyArray &key) const {

    Uint8Vector decrypted(ciphertext.size() - crypto_secretbox_MACBYTES);
    if (0 == crypto_secretbox_open_easy(
            decrypted.data(), ciphertext.data(), ciphertext.size(), nonce.data(), key.data())) {
        return decrypted;
    }
    return make_error(CipherError::AE_AEAD_OPEN_ERROR, "x_salsa_20_poly_1305 open");
}

class XChacha20Poly1305 : public Cipher {
public:
    [[nodiscard]] SharedKeyResult shared_key(const KeyArray &secret_key, const KeyArray &public_key) const override;
    [[nodiscard]] SealResult seal(Uint8View message, const nonce_array &nonce, const KeyArray &key) const override;
    [[nodiscard]] OpenResult open(Uint8View ciphertext, const nonce_array &nonce, const KeyArray &key) const override;
};

XChacha20Poly1305::SharedKeyResult XChacha20Poly1305::shared_key(
        const KeyArray &secret_key, const KeyArray &public_key) const {

    KeyArray shared_key;
    if (crypto_scalarmult(shared_key.data(), secret_key.data(), public_key.data()) != 0) {
        return make_error(CipherError::AE_SCALARMULT_ERROR);
    }
    uint8_t c = 0;
    for (const auto &k : shared_key) {
        c |= k;
    }
    if (c == 0) {
        return make_error(CipherError::AE_WEAK_PUBKEY);
    }
    uint8_t nonce[16]{};
    if (crypto_core_hchacha20(shared_key.data(), nonce, shared_key.data(), nullptr) != 0) {
        return make_error(CipherError::AE_HCHACHA20_ERROR);
    }
    return shared_key;
}

XChacha20Poly1305::SealResult XChacha20Poly1305::seal(
        Uint8View message, const nonce_array &nonce, const KeyArray &key) const {

    Uint8Vector ciphertext(message.size() + crypto_secretbox_xchacha20poly1305_MACBYTES);
    if (0 == crypto_secretbox_xchacha20poly1305_easy(
                ciphertext.data(), message.data(), message.size(), nonce.data(), key.data())) {
        return ciphertext;
    }
    return make_error(CipherError::AE_AEAD_SEAL_ERROR, "x_chacha_20_poly_1305 seal");
}

XChacha20Poly1305::OpenResult XChacha20Poly1305::open(
        Uint8View ciphertext, const nonce_array &nonce, const KeyArray &key) const {

    Uint8Vector decrypted(ciphertext.size() - crypto_box_curve25519xchacha20poly1305_MACBYTES);
    if (0 == crypto_secretbox_xchacha20poly1305_open_easy(
                decrypted.data(), ciphertext.data(), ciphertext.size(), nonce.data(), key.data())) {
        return decrypted;
    }
    return make_error(CipherError::AE_AEAD_OPEN_ERROR, "x_chacha_20_poly_1305 open");
}

CreateCipherResult create_cipher(CryptoConstruction value) {

    switch (value) {
    case CryptoConstruction::X_SALSA_20_POLY_1305: {
        static const XSalsa20Poly1305 result;
        return (Cipher *) &result;
    }
    case CryptoConstruction::X_CHACHA_20_POLY_1305: {
        static const XChacha20Poly1305 result;
        return (Cipher *) &result;
    }
    default:
        return make_error(CreateCipherError::AE_UNKNOWN_CIPHER, fmt::to_string(value));
    }
}

} // namespace ag::dnscrypt
