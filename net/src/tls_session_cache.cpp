#include "tls_session_cache.h"
#include "common/utils.h"
#include <cassert>

ag::Logger ag::tls_session_cache::log {"TLS session cache"};
std::mutex ag::tls_session_cache::mtx;
std::unordered_map<std::string, std::list<ag::ssl_session_ptr>> ag::tls_session_cache::caches_by_url;

static int get_ex_data_idx();
const int ag::tls_session_cache::SSL_EX_DATA_IDX = get_ex_data_idx();

void ag::tls_session_cache::save_session(SSL *ssl, SSL_SESSION *session) {
    auto *cache = (tls_session_cache *) SSL_get_ex_data(ssl, SSL_EX_DATA_IDX);
    if (!cache) {
        dbglog(log, "SSL object is not associated with a cache");
        return;
    }
    std::scoped_lock l(mtx);
    auto &sessions = caches_by_url[cache->url]; // Create if not exists
    if (sessions.size() == MAX_SIZE_PER_URL) {
        dbglog(log, "Session cache for {} is full at {} sessions, truncating", cache->url, sessions.size());
        sessions.pop_front();
    }
    sessions.emplace_back(session);
    dbglog(log, "Session saved, {} sessions available for {}", sessions.size(), cache->url);
}

ag::ssl_session_ptr ag::tls_session_cache::get_session() {
    std::scoped_lock l(mtx);
    auto it = caches_by_url.find(url);
    if (it == caches_by_url.end() || it->second.empty()) {
        dbglog(log, "Session cache for {} is empty", url);
        return nullptr;
    }
    auto &sessions = it->second;
    ssl_session_ptr session = std::move(sessions.back());
    sessions.pop_back();
    dbglog(log, "Returning cached session, {} sessions remaining for {}", sessions.size(), url);
    return session;
}

int ag::tls_session_cache::session_new_cb(SSL *ssl, SSL_SESSION *session) {
    if (!ssl || !session) {
        dbglog(log, "SSL or SSL_SESSION is nullptr");
        return 0;
    }
    save_session(ssl, session);
    return 1; // Return 1 to take ownership of session
}

void ag::tls_session_cache::prepare_ssl_ctx(SSL_CTX *ctx) {
#if 0
    if (char *ssl_keylog_file = getenv("SSLKEYLOGFILE")) {
        static std::unique_ptr<std::FILE, Ftor<&std::fclose>> handle{std::fopen(ssl_keylog_file, "a")};
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

void ag::tls_session_cache::prepare_ssl(SSL *ssl) {
    int ret = SSL_set_ex_data(ssl, SSL_EX_DATA_IDX, this);
    assert(ret == 1);
    (void) ret;
}

ag::tls_session_cache::tls_session_cache(std::string url) : url{std::move(url)} {}

static int get_ex_data_idx() {
    int ret = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    assert(ret > 0);
    return ret;
}
