#pragma once

#include <cstddef>
#include <functional>
#include <type_traits>
#include <utility>
#include <ag_defs.h>
#include <ag_utils.h>
#include "dns_crypt_consts.h"
#include <dns_crypt_utils.h>

namespace ag::dnscrypt {

/**
 * Cipher strategy base class
 */
class cipher {
public:
    struct shared_key_result {
        key_array shared_key;
        err_string error;
    };

    struct seal_result {
        uint8_vector ciphertext;
        err_string error;
    };

    struct open_result {
        uint8_vector decrypted;
        err_string error;
    };

    cipher() = default;
    cipher(cipher &) = delete;
    cipher &operator=(cipher &) = delete;
    virtual ~cipher() = default;

    /**
     * Compute shared key
     * @param secret_key
     * @param public_key
     * @return Shared key result
     */
    virtual shared_key_result shared_key(const key_array &secret_key, const key_array &public_key) const = 0;

    /**
     * Encrypt message to ciphertext
     * @param message Message to encrypt
     * @param nonce Nonce
     * @param key Key
     * @return Seal result
     */
    virtual seal_result seal(uint8_view message, const nonce_array &nonce, const key_array &key) const = 0;

    /**
     * Decrypt ciphertext to message
     * @param ciphertext Ciphertext to decrypt
     * @param nonce Nonce
     * @param key Key
     * @return Open result
     */
    virtual open_result open(uint8_view ciphertext, const nonce_array &nonce, const key_array &key) const = 0;
};

struct create_cipher_result {
    const cipher *cipher_ptr;
    err_string error;
};

create_cipher_result create_cipher(crypto_construction value);

template<typename F, typename... Ts>
auto apply_cipher_function(crypto_construction local_crypto_construction, F&& f, Ts&&... xs) {
    auto[cipher_ptr, cipher_err] = create_cipher(local_crypto_construction);
    if (cipher_err) {
        using result_type = std::invoke_result_t<F&&, decltype(cipher_ptr), Ts&&...>;
        static constexpr utils::make_error<result_type> make_error;
        return make_error(std::move(cipher_err));
    }
    return std::invoke(std::forward<F>(f), cipher_ptr, std::forward<Ts>(xs)...);
}

/**
 * Define cipher_FUNCTION_NAME(crypto_construction crypto_construction, params...) function
 * with same signature and return type as in cipher virtual functions
 */
#define AG_DNSCRYPT_CIPHER_FUNCTION(FUNCTION_NAME) \
template<typename... Ts> \
auto cipher_ ## FUNCTION_NAME (crypto_construction crypto_construction, Ts&&... xs) { \
    return apply_cipher_function(crypto_construction, &cipher:: FUNCTION_NAME, std::forward<Ts>(xs)...); \
}

AG_DNSCRYPT_CIPHER_FUNCTION(shared_key)
AG_DNSCRYPT_CIPHER_FUNCTION(seal)
AG_DNSCRYPT_CIPHER_FUNCTION(open)

#undef AG_DNSCRYPT_CIPHER_FUNCTION

} // namespace ag::dnscrypt
