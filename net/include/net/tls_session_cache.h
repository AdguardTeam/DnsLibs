#pragma once

#include <openssl/ssl.h>
#include "common/defs.h"
#include "common/logger.h"
#include <unordered_map>
#include <list>
#include <string>

namespace ag {

using SslSessionPtr = bssl::UniquePtr<SSL_SESSION>;

/**
 * A cache of recently seen SSL_SESSIONs for the given URL.
 * The cache is static and thread safe. Different instances of this
 * class with the same URL are backed by the same cache.
 */
class TlsSessionCache {
private:
    std::string m_url;

    static Logger m_log;
    static std::mutex m_mtx;
    static std::unordered_map<std::string, std::list<SslSessionPtr>> m_caches_by_url;

    static constexpr size_t MAX_SIZE_PER_URL = 5;
    static const int SSL_EX_DATA_IDX;

    static void save_session(SSL *ssl, SSL_SESSION *session);
    static int session_new_cb(SSL *ssl, SSL_SESSION *session);

public:
    /** Set the session cache mode and the new session callback. */
    static void prepare_ssl_ctx(SSL_CTX *ctx);

    /** Open the cache for the specified URL. */
    explicit TlsSessionCache(std::string url);

    /** Associate an SSL object with this cache to save established sessions. */
    void prepare_ssl(SSL *ssl);

    /**
     * Get the most recently discovered session, or nullptr if there are no sessions.
     * For TLS 1.3 compatibility and maximum privacy, will only be returned once,
     * so the caller gains ownership of the session.
     */
    SslSessionPtr get_session();
};

} // namespace ag
