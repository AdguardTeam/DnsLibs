#include "dns/net/tls_session_cache.h"
#include "common/utils.h"
#include <cassert>

namespace ag::dns {

Logger TlsSessionCache::m_log{"TLS session cache"};
std::mutex TlsSessionCache::m_mtx;
std::unordered_map<std::string, std::list<SslSessionPtr>> TlsSessionCache::m_caches_by_url;

static int get_ex_data_idx();
const int TlsSessionCache::SSL_EX_DATA_IDX = get_ex_data_idx();

void TlsSessionCache::save_session(SSL *ssl, SSL_SESSION *session) {
    auto *cache = (TlsSessionCache *) SSL_get_ex_data(ssl, SSL_EX_DATA_IDX);
    if (!cache) {
        dbglog(m_log, "SSL object is not associated with a cache");
        return;
    }
    std::scoped_lock l(m_mtx);
    auto &sessions = m_caches_by_url[cache->m_url]; // Create if not exists
    if (sessions.size() == MAX_SIZE_PER_URL) {
        dbglog(m_log, "Session cache for {} is full at {} sessions, truncating", cache->m_url, sessions.size());
        sessions.pop_front();
    }
    sessions.emplace_back(session);
    dbglog(m_log, "Session saved, {} sessions available for {}", sessions.size(), cache->m_url);
}

SslSessionPtr TlsSessionCache::get_session() {
    std::scoped_lock l(m_mtx);
    auto it = m_caches_by_url.find(m_url);
    if (it == m_caches_by_url.end() || it->second.empty()) {
        dbglog(m_log, "Session cache for {} is empty", m_url);
        return nullptr;
    }
    auto &sessions = it->second;
    SslSessionPtr session = std::move(sessions.back());
    sessions.pop_back();
    dbglog(m_log, "Returning cached session, {} sessions remaining for {}", sessions.size(), m_url);
    return session;
}

int TlsSessionCache::session_new_cb(SSL *ssl, SSL_SESSION *session) {
    if (!ssl || !session) {
        dbglog(m_log, "SSL or SSL_SESSION is nullptr");
        return 0;
    }
    save_session(ssl, session);
    return 1; // Return 1 to take ownership of session
}

void TlsSessionCache::prepare_ssl_ctx(SSL_CTX *ctx) {
#if 0
    if (char *ssl_keylog_file = getenv("SSLKEYLOGFILE")) {
        static UniquePtr<std::FILE, &std::fclose> handle{std::fopen(ssl_keylog_file, "a")};
        SSL_CTX_set_keylog_callback(ctx,
                [] (const SSL *, const char *line) {
                    fprintf(handle.get(), "%s\n", line);
                    fflush(handle.get());
                });
    }
#endif

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(ctx, session_new_cb);
}

void TlsSessionCache::prepare_ssl(SSL *ssl) {
    int ret = SSL_set_ex_data(ssl, SSL_EX_DATA_IDX, this);
    assert(ret == 1);
    (void) ret;
}

TlsSessionCache::TlsSessionCache(std::string url)
        : m_url{std::move(url)} {
}

static int get_ex_data_idx() {
    int ret = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    assert(ret > 0);
    return ret;
}

} // namespace ag::dns
