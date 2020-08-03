#include <utility>
#include <sodium.h>
#include "dns_crypt_cipher.h"
#include <ag_utils.h>

static constexpr uint8_t ZEROS[16]{};

namespace ag::dnscrypt {

static const struct ensure_sodium_init {
    ensure_sodium_init() noexcept {
        int result = ::sodium_init();
        assert(result == 0); // `0` means `initialized for the first time`
    }
} _ensure_sodium_init [[maybe_unused]];

class x_salsa_20_poly_1305 : public cipher {
public:
    shared_key_result shared_key(const key_array &secret_key, const key_array &public_key) const override;
    seal_result seal(uint8_view message, const nonce_array &nonce, const key_array &key) const override;
    open_result open(uint8_view ciphertext, const nonce_array &nonce, const key_array &key) const override;
};

} // namespace ag::dnscrypt

ag::dnscrypt::x_salsa_20_poly_1305::shared_key_result ag::dnscrypt::x_salsa_20_poly_1305::shared_key(
        const key_array &secret_key, const key_array &public_key) const {
    static constexpr utils::make_error<shared_key_result> make_error;
    key_array shared_key{};
    if (crypto_scalarmult(shared_key.data(), secret_key.data(), public_key.data()) != 0) {
        return make_error("Can not scalarmult");
    }
    if (crypto_core_hsalsa20(shared_key.data(), ZEROS, shared_key.data(), nullptr) != 0) {
        return make_error("Can not hsalsa20");
    }
    return {shared_key, std::nullopt};
}

ag::dnscrypt::x_salsa_20_poly_1305::seal_result ag::dnscrypt::x_salsa_20_poly_1305::seal(uint8_view message,
                                                                                         const nonce_array &nonce,
                                                                                         const key_array &key) const {
    static constexpr utils::make_error<seal_result> make_error;
    uint8_vector ciphertext(message.size() + crypto_secretbox_MACBYTES);
    if (crypto_secretbox_easy(ciphertext.data(), message.data(), message.size(), nonce.data(), key.data()) == 0) {
        return {std::move(ciphertext), std::nullopt};
    }
    return make_error("Can not x_salsa_20_poly_1305 seal");
}

ag::dnscrypt::x_salsa_20_poly_1305::open_result ag::dnscrypt::x_salsa_20_poly_1305::open(uint8_view ciphertext,
                                                                                         const nonce_array &nonce,
                                                                                         const key_array &key) const {
    static constexpr utils::make_error<open_result> make_error;
    uint8_vector decrypted(ciphertext.size() - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(decrypted.data(), ciphertext.data(), ciphertext.size(), nonce.data(), key.data()) ==
                0) {
        return {std::move(decrypted), std::nullopt};
    }
    return make_error("Can not x_salsa_20_poly_1305 open");
}

namespace ag::dnscrypt {

class x_chacha_20_poly_1305 : public cipher {
public:
    shared_key_result shared_key(const key_array &secret_key, const key_array &public_key) const override;
    seal_result seal(uint8_view message, const nonce_array &nonce, const key_array &key) const override;
    open_result open(uint8_view ciphertext, const nonce_array &nonce, const key_array &key) const override;
};

} // namespace ag::dnscrypt

ag::dnscrypt::x_chacha_20_poly_1305::shared_key_result ag::dnscrypt::x_chacha_20_poly_1305::shared_key(
        const key_array &secret_key, const key_array &public_key) const {
    static constexpr utils::make_error<shared_key_result> make_error;
    key_array shared_key;
    if (crypto_scalarmult(shared_key.data(), secret_key.data(), public_key.data()) != 0) {
        return make_error("Can not scalarmult");
    }
    uint8_t c = 0;
    for (const auto &k : shared_key) {
        c |= k;
    }
    if (c == 0) {
        return make_error("Weak public key", shared_key);
    }
    uint8_t nonce[16]{};
    if (crypto_core_hchacha20(shared_key.data(), nonce, shared_key.data(), nullptr) != 0) {
        return make_error("Can not hchacha20");
    }
    return {shared_key, std::nullopt};
}

ag::dnscrypt::x_chacha_20_poly_1305::seal_result ag::dnscrypt::x_chacha_20_poly_1305::seal(uint8_view message,
                                                                                           const nonce_array &nonce,
                                                                                           const key_array &key) const {
    static constexpr utils::make_error<seal_result> make_error;
    uint8_vector ciphertext(message.size() + crypto_secretbox_xchacha20poly1305_MACBYTES);
    if (crypto_secretbox_xchacha20poly1305_easy(ciphertext.data(), message.data(), message.size(), nonce.data(),
                                                key.data()) == 0) {
        return {std::move(ciphertext), std::nullopt};
    }
    return make_error("Can not x_chacha_20_poly_1305 seal");
}

ag::dnscrypt::x_chacha_20_poly_1305::open_result ag::dnscrypt::x_chacha_20_poly_1305::open(uint8_view ciphertext,
                                                                                           const nonce_array &nonce,
                                                                                           const key_array &key) const {
    static constexpr utils::make_error<open_result> make_error;
    uint8_vector decrypted(ciphertext.size() - crypto_box_curve25519xchacha20poly1305_MACBYTES);
    if (crypto_secretbox_xchacha20poly1305_open_easy(decrypted.data(), ciphertext.data(), ciphertext.size(),
                                                     nonce.data(), key.data()) == 0) {
        return {std::move(decrypted), std::nullopt};
    }
    return make_error("Can not x_chacha_20_poly_1305 open");
}

ag::dnscrypt::create_cipher_result ag::dnscrypt::create_cipher(crypto_construction value) {
    static constexpr utils::make_error<create_cipher_result> make_error;
    switch (value) {
    case crypto_construction::X_SALSA_20_POLY_1305: {
        static const x_salsa_20_poly_1305 result;
        return {&result, std::nullopt};
    }
    case crypto_construction::X_CHACHA_20_POLY_1305: {
        static const x_chacha_20_poly_1305 result;
        return {&result, std::nullopt};
    }
    default:
        return make_error(AG_FMT("Can not create cipher with value = {}", value));
    }
}
