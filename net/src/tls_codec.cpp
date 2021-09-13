#include <numeric>
#include "tls_codec.h"


using namespace ag;


static constexpr size_t ENCRYPTED_READ_CHUNK_SIZE = 4 * 1024;
/// Cover the most common DNS response sizes
static constexpr size_t DECRYPTED_READ_CHUNK_SIZE = 512;


static uint8_vector make_alpn(const std::vector<std::string> &protos) {
    uint8_vector alpn;
    alpn.reserve(protos.size()
            + std::accumulate(protos.begin(), protos.end(), 0,
                    [] (size_t acc, const std::string &p) { return acc + p.length(); }));

    for (const std::string &p : protos) {
        alpn.push_back(p.length());
        alpn.insert(alpn.end(), p.data(), p.data() + p.length());
    }

    return alpn;
}

tls_codec::tls_codec(const certificate_verifier *cert_verifier, tls_session_cache *session_cache)
    : cert_verifier(cert_verifier)
    , session_cache(session_cache)
    , log(create_logger(__func__))
{}

std::optional<tls_codec::error> tls_codec::connect(const std::string &sni, std::vector<std::string> alpn) {
    std::unique_ptr<SSL_CTX, ftor<&SSL_CTX_free>> ctx{ SSL_CTX_new(TLS_client_method()) };
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_cert_verify_callback(ctx.get(), ssl_verify_callback, this);
    tls_session_cache::prepare_ssl_ctx(ctx.get());

    this->ssl.reset(SSL_new(ctx.get()));

    if (!sni.empty()) {
        SSL_set_tlsext_host_name(this->ssl.get(), sni.c_str());
    }

    if (!alpn.empty()) {
        uint8_vector serialized = make_alpn(alpn);
        int r = SSL_set_alpn_protos(this->ssl.get(), serialized.data(), serialized.size());
        if (r != 0) {
            return error{ "Failed to set ALPN protocols" };
        }
    }

    this->session_cache->prepare_ssl(this->ssl.get());

    if (ssl_session_ptr session = this->session_cache->get_session()) {
        SSL_set_session(this->ssl.get(), session.get()); // UpRefs the session
    }

    SSL_set_bio(this->ssl.get(), BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
    SSL_set_connect_state(this->ssl.get());

    return this->proceed_handshake();
}

bool tls_codec::want_send_encrypted() const {
    return this->ssl != nullptr && 0 < BIO_pending(SSL_get_wbio(this->ssl.get()));
}

bool tls_codec::want_read_decrypted() const {
    return this->is_connected()
            && (0 < BIO_pending(SSL_get_rbio(this->ssl.get())) || 0 < SSL_pending(this->ssl.get()));
}

bool tls_codec::is_connected() const {
    return this->ssl != nullptr && SSL_is_init_finished(this->ssl.get());
}

tls_codec::send_encrypted_result tls_codec::send_encrypted() {
    if (this->ssl == nullptr) {
        return error{ "Invalid state" };
    }

    BIO *write_bio = SSL_get_wbio(this->ssl.get());

    uint8_vector buffer(std::min(BIO_pending(write_bio), ENCRYPTED_READ_CHUNK_SIZE));
    int r = BIO_read(write_bio, buffer.data(), (int)buffer.size());
    if (r < 0 && !BIO_should_retry(write_bio)) {
        return error{ "Failed to get buffered data" };
    }

    buffer.resize(r);
    return chunk{ { std::move(buffer) } };
}

std::optional<tls_codec::error> tls_codec::recv_encrypted(uint8_view buffer) {
    if (this->ssl == nullptr) {
        return error{ "Invalid state" };
    }

    BIO *read_bio = SSL_get_rbio(this->ssl.get());
    int r = BIO_write(read_bio, buffer.data(), (int)buffer.size());
    if (r < 0) {
        return error{ "Failed to write received data in crypto buffer" };
    }

    if (!this->is_connected()) {
        return this->proceed_handshake();
    }

    return std::nullopt;
}

tls_codec::read_decrypted_result tls_codec::read_decrypted() {
    if (!this->is_connected()) {
        return error{ "Invalid state" };
    }

    uint8_vector buffer(DECRYPTED_READ_CHUNK_SIZE);

    int r = SSL_read(this->ssl.get(), buffer.data(), (int)buffer.size());
    if (r <= 0) {
        r = SSL_get_error(this->ssl.get(), r);
        switch (r) {
        case SSL_ERROR_ZERO_RETURN:
            return error{ "Remote server unexpectedly closed TLS connection" };
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            r = 0;
            break;
        default:
            return error{ AG_FMT("Failed to read from TLS connection ({})", SSL_get_error(this->ssl.get(), r)) };
        }
    }

    buffer.resize(r);
    return chunk{ std::move(buffer) };
}

tls_codec::write_decrypted_result tls_codec::write_decrypted(uint8_view buffer) {
    if (!this->is_connected()) {
        return error{ "Invalid state" };
    }

    int r = SSL_write(this->ssl.get(), buffer.data(), (int)buffer.size());
    if (r <= 0 && r != SSL_ERROR_WANT_READ && r != SSL_ERROR_WANT_WRITE) {
        r = SSL_get_error(this->ssl.get(), r);
        if (r == SSL_ERROR_ZERO_RETURN) {
            return error{ "Remote server unexpectedly closed TLS connection" };
        } else {
            return error{ AG_FMT("Failed to write in TLS connection ({})", r) };
        }
    }

    return decrypted_bytes_written{ (size_t)r };
}

int tls_codec::ssl_verify_callback(X509_STORE_CTX *ctx, void *arg) {
    SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    auto *self = (tls_codec *)arg;

    if (self->cert_verifier == nullptr) {
        dbglog(self->log, "Cannot verify certificate due to verifier is not set");
        return 0;
    }

    if (err_string err = self->cert_verifier->verify(ctx, SSL_get_servername(ssl, SSL_get_servername_type(ssl)));
            err.has_value()) {
        dbglog(self->log, "Failed to verify certificate: {}", err.value());
        return 0;
    }

    tracelog(self->log, "Verified successfully");
    return 1;
}

std::optional<tls_codec::error> tls_codec::proceed_handshake() {
    std::optional<tls_codec::error> err;

    int r = SSL_do_handshake(this->ssl.get());
    if (r < 0) {
        r = SSL_get_error(this->ssl.get(), r);
        if (r != SSL_ERROR_WANT_READ && r != SSL_ERROR_WANT_WRITE) {
            err = { AG_FMT("Failed to perform handshake ({})", r) };
        }
    }

    return err;
}
