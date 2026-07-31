#include <cstring>
#include <numeric>
#include <variant>

#include "common/tls/make_ssl.h"
#include "tls_codec.h"

namespace ag::dns {

static constexpr size_t ENCRYPTED_READ_CHUNK_SIZE = 4 * 1024;
/// Cover the most common DNS response sizes
static constexpr size_t DECRYPTED_READ_CHUNK_SIZE = 512;

static Uint8Vector make_alpn(const std::vector<std::string> &protos) {
    Uint8Vector alpn;
    alpn.reserve(protos.size() + std::accumulate(protos.begin(), protos.end(), 0, [](size_t acc, const std::string &p) {
        return acc + p.length();
    }));

    for (const std::string &p : protos) {
        alpn.push_back(p.length());
        alpn.insert(alpn.end(), p.data(), p.data() + p.length());
    }

    return alpn;
}

TlsCodec::TlsCodec(const CertificateVerifier *cert_verifier, TlsSessionCache *session_cache,
        std::vector<CertFingerprint> fingerprint)
        : m_cert_verifier(cert_verifier)
        , m_session_cache(session_cache)
        , m_log(__func__)
        , m_fingerprints(std::move(fingerprint)) {
}

Error<TlsCodec::TlsError> TlsCodec::connect(const std::string &sni, std::vector<std::string> alpn, bool enable_pq) {
    m_server_name = sni;

    Uint8Vector serialized_alpn = make_alpn(alpn);
    // The session is consumed by `make_ssl()`, which up-refs it.
    SslSessionPtr session = m_session_cache->get_session();

    // Imitate Chrome's ClientHello so that our TLS fingerprint is not distinguishable from a
    // browser's. `make_ssl()` also takes care of the SNI,
    // the ALPN list, the key share groups and putting the connection into the client state.
    std::variant<tls::SslPtr, std::string> ssl = tls::make_ssl({
            .profile = tls::TlsClientProfile::CHROME,
            .protocol = tls::SslProtocol::TLS,
            .alpn_protos = {serialized_alpn.data(), serialized_alpn.size()},
            .sni = m_server_name.empty() ? nullptr : m_server_name.c_str(),
            .verify_callback = ssl_verify_callback,
            .verify_arg = this,
            .post_quantum = enable_pq,
            .new_session_cb = TlsSessionCache::session_new_cb,
            .resume_session = session.get(),
    });
    if (const auto *error = std::get_if<std::string>(&ssl)) {
        dbglog(m_log, "Failed to create SSL: {}", *error);
        return make_error(TlsError::AE_SSL_INIT_FAILED, *error);
    }
    m_ssl = std::move(std::get<tls::SslPtr>(ssl));

    m_session_cache->prepare_ssl(m_ssl.get());
    SSL_set_bio(m_ssl.get(), BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));

    return this->proceed_handshake();
}

bool TlsCodec::want_send_encrypted() const {
    return m_ssl != nullptr && 0 < BIO_pending(SSL_get_wbio(m_ssl.get()));
}

bool TlsCodec::want_read_decrypted() const {
    return this->is_connected() && (0 < BIO_pending(SSL_get_rbio(m_ssl.get())) || 0 < SSL_pending(m_ssl.get()));
}

bool TlsCodec::is_connected() const {
    return m_ssl != nullptr && SSL_is_init_finished(m_ssl.get());
}

TlsCodec::SendEncryptedResult TlsCodec::send_encrypted() {
    if (m_ssl == nullptr) {
        return make_error(TlsError::AE_INVALID_STATE);
    }

    BIO *write_bio = SSL_get_wbio(m_ssl.get());

    Uint8Vector buffer(std::min(size_t(BIO_pending(write_bio)), ENCRYPTED_READ_CHUNK_SIZE));
    int r = BIO_read(write_bio, buffer.data(), (int) buffer.size());
    if (r < 0) {
        if (!BIO_should_retry(write_bio)) {
            return make_error(TlsError::AE_BUFFER_ERROR);
        }
        r = 0;
    }

    buffer.resize(r);
    return Chunk{{std::move(buffer)}};
}

Error<TlsCodec::TlsError> TlsCodec::recv_encrypted(Uint8View buffer) {
    if (m_ssl == nullptr) {
        return make_error(TlsError::AE_INVALID_STATE);
    }

    BIO *read_bio = SSL_get_rbio(m_ssl.get());
    int r = BIO_write(read_bio, buffer.data(), (int) buffer.size());
    if (r < 0) {
        return make_error(TlsError::AE_WRITE_ERROR);
    }

    if (!this->is_connected()) {
        return this->proceed_handshake();
    }

    return {};
}

TlsCodec::ReadDecryptedResult TlsCodec::read_decrypted() {
    if (!this->is_connected()) {
        return make_error(TlsError::AE_INVALID_STATE);
    }

    Uint8Vector buffer(DECRYPTED_READ_CHUNK_SIZE);

    int r = SSL_read(m_ssl.get(), buffer.data(), (int) buffer.size());
    if (r <= 0) {
        r = SSL_get_error(m_ssl.get(), r);
        switch (r) {
        case SSL_ERROR_ZERO_RETURN:
            return make_error(TlsError::AE_UNEXPECTED_EOF);
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            r = 0;
            break;
        default:
            return make_error(TlsError::AE_READ_ERROR, AG_FMT("{}", r));
        }
    }

    buffer.resize(r);
    return Chunk{std::move(buffer)};
}

TlsCodec::WriteDecryptedResult TlsCodec::write_decrypted(Uint8View buffer) {
    if (!this->is_connected()) {
        return make_error(TlsError::AE_INVALID_STATE);
    }

    int r = SSL_write(m_ssl.get(), buffer.data(), (int) buffer.size());
    if (r <= 0 && r != SSL_ERROR_WANT_READ && r != SSL_ERROR_WANT_WRITE) {
        r = SSL_get_error(m_ssl.get(), r);
        if (r == SSL_ERROR_ZERO_RETURN) {
            return make_error(TlsError::AE_UNEXPECTED_EOF);
        } else {
            auto err = make_error(OSslError(r));
            return make_error(TlsError::AE_WRITE_ERROR, err);
        }
    }

    return DecryptedBytesWritten{(size_t) r};
}

std::optional<std::string> TlsCodec::get_alpn_selected() const {
    if (!m_ssl) {
        return std::nullopt;
    }
    const uint8_t *data;
    unsigned len = 0;
    SSL_get0_alpn_selected(m_ssl.get(), &data, &len);
    if (len == 0) {
        return std::nullopt;
    }
    return std::make_optional<std::string>((const char *) data, len);
}

int TlsCodec::ssl_verify_callback(X509_STORE_CTX *ctx, void *arg) {
    auto *self = (TlsCodec *) arg;

    if (self->m_cert_verifier == nullptr) {
        warnlog(self->m_log, "Cannot verify certificate for '{}' due to verifier is not set", self->m_server_name);
        return 0;
    }

    if (auto err = self->m_cert_verifier->verify(ctx, self->m_server_name, self->m_fingerprints)) {
        warnlog(self->m_log, "Failed to verify certificate for '{}': {}", self->m_server_name, *err);
        warnlog(self->m_log, "  {}", get_cert_diagnostic_info(ctx));
        return 0;
    }

    tracelog(self->m_log, "Verified successfully");
    return 1;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
Error<TlsCodec::TlsError> TlsCodec::proceed_handshake() {
    Error<TlsCodec::TlsError> err;

    int r = SSL_do_handshake(m_ssl.get());
    if (r < 0) {
        r = SSL_get_error(m_ssl.get(), r);
        if (r != SSL_ERROR_WANT_READ && r != SSL_ERROR_WANT_WRITE) {
            std::string errors;
            uint32_t error;
            const char *file;
            int line;
            while ((error = ERR_get_error_line(&file, &line)) != 0) {
                if (const char *name;
                        (name = strrchr(file, '/')) != nullptr || (name = strrchr(file, '\\')) != nullptr) {
                    file = name + 1;
                }
                errors += AG_FMT("\t{}:{}:{}\n", file, line, ERR_error_string(error, nullptr));
            }

            err = make_error(TlsError::AE_HANDSHAKE_ERROR, AG_FMT("TLS handshake failed (\n{})", errors));
        }
    }

    return err;
}
#pragma GCC diagnostic pop

} // namespace ag::dns
