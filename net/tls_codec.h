#pragma once


#include <memory>
#include <variant>
#include <optional>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "common/defs.h"
#include "common/logger.h"
#include "dns/common/dns_defs.h"
#include "dns/net/certificate_verifier.h"
#include "dns/net/tls_session_cache.h"


namespace ag {
namespace dns {


class TlsCodec {
public:
    enum class OSslError {
    };
    enum class TlsError {
        AE_INVALID_STATE,
        AE_UNEXPECTED_EOF,
        AE_ALPN_SET_FAILED,
        AE_BUFFER_ERROR,
        AE_WRITE_ERROR,
        AE_READ_ERROR,
        AE_HANDSHAKE_ERROR,
    };

    struct Chunk {
        Uint8Vector data;
    };

    using SendEncryptedResult = Result<Chunk, TlsError>;
    using ReadDecryptedResult = Result<Chunk, TlsError>;

    struct DecryptedBytesWritten {
        size_t num;
    };
    using WriteDecryptedResult = Result<DecryptedBytesWritten, TlsError>;

    TlsCodec(const CertificateVerifier *cert_verifier, TlsSessionCache *session_cache);

    ~TlsCodec() = default;

    /**
     * Initiate the TLS session
     * @param sni server name
     * @param alpn application protocols
     * @return none if started successfully
     */
    Error<TlsError> connect(const std::string &sni, std::vector<std::string> alpn);

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
    Error<TlsError> recv_encrypted(Uint8View buffer);

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

    Error<TlsError> proceed_handshake();
};

} // namespace dns

// clang format off
template<>
struct ErrorCodeToString<dns::TlsCodec::OSslError> {
    std::string operator()(dns::TlsCodec::OSslError e) {
        const char *msg = SSL_error_description(int(e));
        if (!msg) {
            return AG_FMT("Unknown error: {}", int(e));
        }
        return msg;
    }
};

template<>
struct ErrorCodeToString<dns::TlsCodec::TlsError> {
    std::string operator()(dns::TlsCodec::TlsError e) {
        switch (e) {
        case decltype(e)::AE_INVALID_STATE: return "Invalid state";
        case decltype(e)::AE_UNEXPECTED_EOF: return "Remote server unexpectedly closed TLS connection";
        case decltype(e)::AE_ALPN_SET_FAILED: return "Failed to set ALPN protocols";
        case decltype(e)::AE_BUFFER_ERROR: return "Failed to get buffered data";
        case decltype(e)::AE_WRITE_ERROR: return "Failed to write received data in crypto buffer";
        case decltype(e)::AE_READ_ERROR: return "Failed to read from TLS connection";
        case decltype(e)::AE_HANDSHAKE_ERROR: return "TLS handshake failed";
        }
    }
};
// clang format on

} // namespace ag
