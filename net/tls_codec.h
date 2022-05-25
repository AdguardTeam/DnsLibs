#pragma once


#include <memory>
#include <variant>
#include <optional>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "common/defs.h"
#include "common/logger.h"
#include "net/certificate_verifier.h"
#include "net/tls_session_cache.h"


namespace ag {


class TlsCodec {
public:
    struct Error {
        std::string description;
    };

    struct Chunk {
        Uint8Vector data;
    };

    using SendEncryptedResult = std::variant<Chunk, Error>;
    using ReadDecryptedResult = std::variant<Chunk, Error>;

    struct DecryptedBytesWritten {
        size_t num;
    };
    using WriteDecryptedResult = std::variant<DecryptedBytesWritten, Error>;

    TlsCodec(const CertificateVerifier *cert_verifier, TlsSessionCache *session_cache);
    ~TlsCodec() = default;

    /**
     * Initiate the TLS session
     * @param sni server name
     * @param alpn application protocols
     * @return none if started successfully
     */
    std::optional<Error> connect(const std::string &sni, std::vector<std::string> alpn);

    /**
     * Check if the codec has pending data to send via network
     */
    [[nodiscard]] bool want_send_encrypted() const;

    /**
     * Check if the codec has pending data ready to be decrypted
     */
    [[nodiscard]] bool want_read_decrypted() const;

    /**
     * Check if the TLS session is connected
     */
    [[nodiscard]] bool is_connected() const;

    /**
     * Get an encrypted data chunk to send via network
     */
    SendEncryptedResult send_encrypted();

    /**
     * Feed a data chunk received from network
     */
    std::optional<Error> recv_encrypted(Uint8View buffer);

    /**
     * Read a decrypted data chunk from the TLS session
     */
    ReadDecryptedResult read_decrypted();

    /**
     * Encrypt and send a data chunk
     */
    WriteDecryptedResult write_decrypted(Uint8View buffer);

private:
    const CertificateVerifier *m_cert_verifier = nullptr;
    TlsSessionCache *m_session_cache = nullptr;
    bssl::UniquePtr<SSL> m_ssl;
    Logger m_log;

    static int ssl_verify_callback(X509_STORE_CTX *ctx, void *arg);
    std::optional<Error> proceed_handshake();
};


} // namespace ag
