#include <algorithm>
#include <bitset>
#include <cassert>
#include <cinttypes>

#include "common/defs.h"
#include "common/time_utils.h"
#include "common/utils.h"
#include "dns/net/socket.h"
#include "upstream_doh.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <ldns/ldns.h>
#include <magic_enum.hpp>

#define errlog_id(q_, fmt_, ...) errlog(*((q_)->log), "[{}] " fmt_, (q_)->request_id, ##__VA_ARGS__)
#define infolog_id(q_, fmt_, ...) infolog(*((q_)->log), "[{}] " fmt_, (q_)->request_id, ##__VA_ARGS__)
#define warnlog_id(q_, fmt_, ...) warnlog(*((q_)->log), "[{}] " fmt_, (q_)->request_id, ##__VA_ARGS__)
#define dbglog_id(q_, fmt_, ...) dbglog(*((q_)->log), "[{}] " fmt_, (q_)->request_id, ##__VA_ARGS__)
#define tracelog_id(q_, fmt_, ...) tracelog(*((q_)->log), "[{}] " fmt_, (q_)->request_id, ##__VA_ARGS__)

using namespace std::chrono;

namespace ag {
namespace dns {

struct CurlInitializer {
    CurlInitializer() {
        curl_global_init(CURL_GLOBAL_ALL);
    }

    ~CurlInitializer() {
        curl_global_cleanup();
    }
};

struct DohUpstream::QueryHandle {
    using CURL_ptr = UniquePtr<CURL, &curl_easy_cleanup>;

    enum Flag {
        /// The query uses the proxy
        QHF_PROXIED,
        /// A connection through the proxy has failed and the query was re-routed directly
        QHF_BYPASSED_PROXY,
    };

    const Logger *log = nullptr;
    DohUpstream *upstream = nullptr;
    size_t request_id = 0;
    CURL_ptr curl_handle;
    Error<DnsError> error;
    ldns_buffer_ptr request = nullptr;
    Uint8Vector response;
    bool completed = false;
    std::coroutine_handle<> caller{};
    std::bitset<magic_enum::enum_count<Flag>()> flags;
    std::shared_ptr<curl_slist> resolved_addrs;

    CURL_ptr create_curl_handle();

    bool set_up_proxy(const OutboundProxySettings *settings);

    void cleanup_request();

    void restore_packet_id(ldns_pkt *packet) const {
        ldns_pkt_set_id(packet, this->request_id);
    }

    void complete() {
        completed = true;
        if (caller) {
            std::exchange(caller, nullptr).resume();
        }
    }

    ~QueryHandle() {
        if (!completed && response.empty()) {
            error = make_error(DnsError::AE_SHUTTING_DOWN);
        }
        complete();
    }
};

struct DohUpstream::CheckProxyState {
    DohUpstream *upstream = nullptr;
    std::unique_ptr<Socket> socket;

    static std::unique_ptr<CheckProxyState> start(DohUpstream *upstream, microseconds timeout) {
        SocketFactory *socket_factory = upstream->m_config.socket_factory;

        auto self = std::make_unique<CheckProxyState>();
        self->upstream = upstream;
        self->socket = socket_factory->make_socket({
                utils::TP_TCP,
                upstream->m_options.outbound_interface,
                true,
        });

        const OutboundProxySettings *oproxy_settings = socket_factory->get_outbound_proxy_settings();
        Error<SocketError> error = self->socket->connect({
                &upstream->config().loop,
                SocketAddress(oproxy_settings->address, oproxy_settings->port),
                {on_connected, nullptr, on_close, self.get()},
                timeout,
        });

        if (error) {
            dbglog(upstream->m_log, "Failed to check connectivity with proxy: {}", error->str());
            self.reset();
        }

        return self;
    }

    static void on_connected(void *arg) {
        auto *self = (CheckProxyState *) arg;
        DohUpstream *upstream = self->upstream;

        upstream->m_config.socket_factory->on_successful_proxy_connection();
        upstream->m_check_proxy.reset();
        upstream->retry_pending_queries_directly();
    }

    static void on_close(void *arg, Error<SocketError> error) {
        auto *self = (CheckProxyState *) arg;
        DohUpstream *upstream = self->upstream;

        SocketFactory *factory = upstream->m_config.socket_factory;
        SocketFactory::ProxyConectionFailedResult result = factory->on_proxy_connection_failed(error);

        upstream->m_check_proxy.reset();

        switch (result) {
        case SocketFactory::SFPCFR_CLOSE_CONNECTION:
            upstream->stop_all_with_error(make_error(DnsError::AE_OUTBOUND_PROXY_ERROR));
            break;
        case SocketFactory::SFPCFR_RETRY_DIRECTLY:
            upstream->retry_pending_queries_directly();
            upstream->m_reset_bypassed_proxy_connections_subscribe_id =
                    factory->subscribe_to_reset_bypassed_proxy_connections_event({[](void *arg) {
                        auto *self = (DohUpstream *) arg;
                        self->config().loop.submit([self]() {
                            self->reset_bypassed_proxy_queries();
                        });
                    }});
            break;
        }
    }
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *arg) {
    DohUpstream::QueryHandle *h = (DohUpstream::QueryHandle *) arg;
    size_t full_size = size * nmemb;
    h->response.insert(h->response.end(), (uint8_t *) contents, (uint8_t *) contents + full_size);
    return full_size;
}

curl_socket_t DohUpstream::curl_opensocket(void *clientp, curlsocktype, struct curl_sockaddr *address) {
    auto *self = (DohUpstream *) clientp;
    curl_socket_t curlfd = ::socket(address->family, address->socktype, address->protocol);
    if (curlfd == CURL_SOCKET_BAD) {
        return CURL_SOCKET_BAD;
    }
    SocketAddress addr{&address->addr};
    if (auto error = self->m_config.socket_factory->prepare_fd(curlfd, addr, self->m_options.outbound_interface)) {
        warnlog(self->m_log, "Failed to bind socket to interface: {}", error->str());
        evutil_closesocket(curlfd);
        return CURL_SOCKET_BAD;
    }
    return curlfd;
}

static void curl_share_lockfunc(CURL *, curl_lock_data data, curl_lock_access, void *userptr) {
    auto *m = (std::mutex *) userptr;
    m[data].lock();
}

static void curl_share_unlockfunc(CURL *, curl_lock_data data, void *userptr) {
    auto *m = (std::mutex *) userptr;
    m[data].unlock();
}

// Must be called only once!
static CURLSH *init_curl_share() {
    static std::mutex mtx[CURL_LOCK_DATA_LAST];
    CURLSH *share = curl_share_init();
    curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
    curl_share_setopt(share, CURLSHOPT_USERDATA, &mtx[0]);
    curl_share_setopt(share, CURLSHOPT_LOCKFUNC, curl_share_lockfunc);
    curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, curl_share_unlockfunc);
    return share;
}

static CURLSH *get_curl_share() {
    static UniquePtr<CURLSH, &curl_share_cleanup> curl_share(init_curl_share());
    return curl_share.get();
}

static int verbose_callback(CURL *, curl_infotype type, char *data, size_t size, void *arg) {
    auto *h = (DohUpstream::QueryHandle *) arg;
    if (type == CURLINFO_TEXT) {
        dbglog_id(h, "CURL: {}", ag::utils::trim(std::string_view{data, size}));
    } else if (type == CURLINFO_HEADER_IN) {
        dbglog_id(h, "CURL: < {}", ag::utils::trim(std::string_view{data, size}));
    } else if (type == CURLINFO_HEADER_OUT) {
        dbglog_id(h, "CURL: > {}", ag::utils::trim(std::string_view{data, size}));
    }
    return 0;
}

DohUpstream::QueryHandle::CURL_ptr DohUpstream::QueryHandle::create_curl_handle() {
    CURL_ptr curl_ptr{curl_easy_init()};
    if (curl_ptr == nullptr) {
        this->error = make_error(DnsError::AE_CURL_ERROR, "Failed to init curl handle");
        return nullptr;
    }

    DohUpstream *doh_upstream = this->upstream;
    ldns_buffer *raw_request = this->request.get();
    uint64_t timeout = doh_upstream->m_options.timeout.count();
    this->resolved_addrs = doh_upstream->m_resolved;
    CURL *curl = curl_ptr.get();
    if (CURLcode e;
            // clang-format off
               CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_URL, doh_upstream->m_curlopt_url.c_str()))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, true))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeout))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_WRITEDATA, this))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_USERAGENT, nullptr))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ldns_buffer_at(raw_request, 0)))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, ldns_buffer_position(raw_request)))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, doh_upstream->m_request_headers.get()))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, doh_upstream->m_curlopt_http_ver))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_PRIVATE, this))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, DohUpstream::ssl_callback))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, this))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false)) // We verify ourselves, see DohUpstream::ssl_callback
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false)) // We verify ourselves, see DohUpstream::ssl_callback
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, true))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, curl_opensocket))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, doh_upstream))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, verbose_callback))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_DEBUGDATA, this))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_VERBOSE, (long) (log->is_enabled(LogLevel::LOG_LEVEL_DEBUG))))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SHARE, get_curl_share()))
            || (doh_upstream->m_resolved != nullptr && CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_RESOLVE, this->resolved_addrs.get())))
            // clang-format on
    ) {
        this->error = make_error(DnsError::AE_CURL_ERROR,
                AG_FMT("Failed to set options on curl handle: {} (id={})", curl_easy_strerror(e), e));
        return nullptr;
    }

    return curl_ptr;
}

bool DohUpstream::QueryHandle::set_up_proxy(const OutboundProxySettings *settings) {
    static constexpr curl_proxytype AG_TO_CURL_PROXY_PROTOCOL[magic_enum::enum_count<OutboundProxyProtocol>()] = {
#ifndef _WIN32
            [(int) OutboundProxyProtocol::HTTP_CONNECT] =
#endif
                    CURLPROXY_HTTP,
#ifndef _WIN32
            [(int) OutboundProxyProtocol::HTTPS_CONNECT] =
#endif
                    CURLPROXY_HTTPS,
#ifndef _WIN32
            [(int) OutboundProxyProtocol::SOCKS4] =
#endif
                    CURLPROXY_SOCKS4,
#ifndef _WIN32
            [(int) OutboundProxyProtocol::SOCKS5] =
#endif
                    CURLPROXY_SOCKS5,
#ifndef _WIN32
            [(int) OutboundProxyProtocol::SOCKS5_UDP] =
#endif
                    CURLPROXY_SOCKS5,
    };

    CURL *curl = this->curl_handle.get();

#define SETOPT_S(curl_, opt_, val_)                                                                                    \
    do {                                                                                                               \
        if (CURLcode e = curl_easy_setopt((curl_), (opt_), (val_)); e != CURLE_OK) {                                   \
            this->error = make_error(                                                                                  \
                    DnsError::AE_CURL_ERROR, make_error(e, AG_FMT("Failed to set option {} on curl handle", opt_)));   \
            return false;                                                                                              \
        }                                                                                                              \
    } while (0)

    SETOPT_S(curl, CURLOPT_PROXYTYPE, AG_TO_CURL_PROXY_PROTOCOL[(int) settings->protocol]);
    SETOPT_S(curl, CURLOPT_PROXY, settings->address.c_str());
    SETOPT_S(curl, CURLOPT_PROXYPORT, settings->port);

    if (const auto &auth_info = settings->auth_info; auth_info.has_value()) {
        SETOPT_S(curl, CURLOPT_PROXYUSERNAME, auth_info->username.c_str());
        SETOPT_S(curl, CURLOPT_PROXYPASSWORD, auth_info->password.c_str());
    }

    SETOPT_S(curl, CURLOPT_PROXY_SSL_VERIFYPEER, false); // We verify ourselves, see DohUpstream::ssl_callback
    SETOPT_S(curl, CURLOPT_PROXY_SSL_VERIFYHOST, false); // We verify ourselves, see DohUpstream::ssl_callback

#undef SETOPT_S

    return true;
}

void DohUpstream::QueryHandle::cleanup_request() {
    if (this->curl_handle) {
        CURLMcode perr [[maybe_unused]] =
                curl_multi_remove_handle(this->upstream->m_pool.handle.get(), this->curl_handle.get());
        assert(perr == CURLM_OK);
        this->curl_handle.reset();
    }
}

std::unique_ptr<DohUpstream::QueryHandle> DohUpstream::create_handle(ldns_pkt *request, Millis timeout) const {
    std::unique_ptr<QueryHandle> h = std::make_unique<QueryHandle>();
    h->log = &m_log;
    h->upstream = (DohUpstream *) this;
    h->request_id = ldns_pkt_id(request);
    ldns_pkt_set_id(request, 0);

    h->request.reset(ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY));
    ldns_status status = ldns_pkt2buffer_wire(h->request.get(), request);
    if (status != LDNS_STATUS_OK) {
        errlog_id(h, "Failed to serialize packet: {}", ldns_get_errorstr_by_id(status));
        h->restore_packet_id(request);
        return nullptr;
    }

    return h;
}

static std::string_view get_host_port(std::string_view url) {
    for (const auto &scheme : {DohUpstream::SCHEME_HTTPS, DohUpstream::SCHEME_H3}) {
        if (!url.starts_with(scheme)) {
            continue;
        }
        url.remove_prefix(scheme.length());
        url = url.substr(0, url.find('/'));
        break;
    }
    return url;
}

static Result<std::string_view, Upstream::InitError> get_host_name(std::string_view url) {
    auto split_result = utils::split_host_port(get_host_port(url));
    if (split_result.has_error()) {
        return make_error(Upstream::InitError::AE_INVALID_ADDRESS);
    }
    return split_result.value().first;
}

int DohUpstream::verify_callback(X509_STORE_CTX *ctx, void *arg) {
    DohUpstream::QueryHandle *handle = (DohUpstream::QueryHandle *) arg;
    DohUpstream *upstream = handle->upstream;

    SSL *ssl = (SSL *) X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    tracelog_id(handle, "{}(): SNI={}", __func__, (sni == nullptr) ? "null" : sni);

    auto host = get_host_name(upstream->m_options.address);

    if (const OutboundProxySettings *proxy_settings = upstream->m_config.socket_factory->get_outbound_proxy_settings();
            proxy_settings != nullptr && proxy_settings->protocol == OutboundProxyProtocol::HTTPS_CONNECT
            && proxy_settings->trust_any_certificate && !host.has_error() && (sni == nullptr || sni != host.value())) {
        tracelog_id(handle, "Trusting any proxy certificate as specified in settings");
        return 1;
    }

    const CertificateVerifier *verifier = upstream->m_config.socket_factory->get_certificate_verifier();
    if (verifier == nullptr) {
        std::string err = "Cannot verify certificate due to verifier is not set";
        dbglog_id(handle, "{}", err);
        handle->error = make_error(DnsError::AE_HANDSHAKE_ERROR, err);
        return 0;
    }

    if (auto err = verifier->verify(ctx, host.value())) {
        dbglog_id(handle, "Failed to verify certificate: {}", *err);
        handle->error = make_error(DnsError::AE_HANDSHAKE_ERROR, *err);
        return 0;
    }

    tracelog_id(handle, "Verified successfully");
    return 1;
}

CURLcode DohUpstream::ssl_callback(CURL *curl, void *sslctx, void *arg) {
    SSL_CTX *ctx = (SSL_CTX *) sslctx;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_cert_verify_callback(ctx, verify_callback, arg);
    return CURLE_OK;
}

static Result<curl_slist_ptr, Upstream::InitError> create_resolved_hosts_list(std::string_view url, const IpAddress &addr) {
    if (std::holds_alternative<std::monostate>(addr)) {
        return (curl_slist_ptr)nullptr;
    }

    std::string_view host_port = get_host_port(url);
    auto split_result = utils::split_host_port(host_port);
    if (split_result.has_error()) {
        make_error(Upstream::InitError::AE_INVALID_ADDRESS);
    }
    auto [host, port_str] = split_result.value();
    uint16_t port = ag::utils::to_integer<uint16_t>(port_str).value_or(DEFAULT_DOH_PORT);

    std::string entry;
    if (const auto *ipv4 = std::get_if<Uint8Array<4>>(&addr); ipv4 != nullptr) {
        const auto &ip = *ipv4;
        entry = AG_FMT("{}:{}:{}.{}.{}.{}", host, port, ip[0], ip[1], ip[2], ip[3]);
    } else {
        const auto &ip = std::get<Uint8Array<16>>(addr);
        entry = AG_FMT("{}:{}:[{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:"
                       "02x}:{:02x}{:02x}]",
                host, port, ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8], ip[9], ip[10], ip[11],
                ip[12], ip[13], ip[14], ip[15]);
    }

    return curl_slist_ptr(curl_slist_append(nullptr, entry.c_str()));
}

curl_pool_ptr DohUpstream::create_pool() const {
    CURLM *pool = curl_multi_init();
    if (pool == nullptr) {
        return nullptr;
    }
    curl_pool_ptr pool_holder = curl_pool_ptr(pool);

    if (CURLMcode e; CURLM_OK != (e = curl_multi_setopt(pool, CURLMOPT_SOCKETFUNCTION, on_socket_update))
            || CURLM_OK != (e = curl_multi_setopt(pool, CURLMOPT_SOCKETDATA, this))
            || CURLM_OK != (e = curl_multi_setopt(pool, CURLMOPT_TIMERFUNCTION, on_pool_timer_event))
            || CURLM_OK != (e = curl_multi_setopt(pool, CURLMOPT_TIMERDATA, this))
            || CURLM_OK != (e = curl_multi_setopt(pool, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX))) {
        errlog(m_log, "Failed to set options of curl pool: {} (id={})", curl_multi_strerror(e), e);
        return nullptr;
    }

    return pool_holder;
}

DohUpstream::DohUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config)
        : Upstream(opts, config)
        , m_log("DOH upstream") {
    static const CurlInitializer ensure_initialized;
}

Error<Upstream::InitError> DohUpstream::init() {
    m_curlopt_url = m_options.address;
    if (m_curlopt_url.starts_with(SCHEME_H3)) {
        m_curlopt_url.replace(0, SCHEME_H3.size(), SCHEME_HTTPS);
        m_curlopt_http_ver = CURL_HTTP_VERSION_3;
    }

    auto create_result = create_resolved_hosts_list(m_options.address, m_options.resolved_server_ip);
    if (create_result.has_error()) {
        return make_error(InitError::AE_INVALID_ADDRESS);
    }
    m_resolved = std::move(create_result.value());

    curl_slist *headers;
    if (nullptr == (headers = curl_slist_append(nullptr, "Content-Type: application/dns-message"))
            || nullptr == (headers = curl_slist_append(headers, "Accept: application/dns-message"))) {
        return make_error(InitError::AE_CURL_HEADERS_INIT_FAILED);
    }
    m_request_headers.reset(headers);

    m_pool.handle = create_pool();
    if (m_pool.handle == nullptr) {
        return make_error(InitError::AE_CURL_POOL_INIT_FAILED);
    }

    if (m_resolved == nullptr) {
        if (!m_options.bootstrap.empty() || SocketAddress(get_host_name(m_options.address).value(), 0).valid()) {
            BootstrapperPtr bootstrapper = std::make_unique<Bootstrapper>(
                    Bootstrapper::Params{get_host_port(m_options.address), DEFAULT_DOH_PORT, m_options.bootstrap,
                            m_options.timeout, m_config, m_options.outbound_interface});
            if (auto err = bootstrapper->init(); !err) {
                m_bootstrapper = std::move(bootstrapper);
            } else {
                return make_error(InitError::AE_BOOTSTRAPPER_INIT_FAILED, err);
            }
        } else {
            return make_error(InitError::AE_EMPTY_BOOTSTRAP);
        }
    }

    m_shutdown_guard = std::make_shared<bool>(true);

    return {};
}

DohUpstream::~DohUpstream() {
    dbglog(m_log, "Destroying...");

    if (auto id = m_reset_bypassed_proxy_connections_subscribe_id; id.has_value()) {
        m_config.socket_factory->unsubscribe_from_reset_bypassed_proxy_connections_event(id.value());
    }

    dbglog(m_log, "Stopping queries...");
    this->stop_all_with_error(make_error(DnsError::AE_SHUTTING_DOWN));
    m_pool.timer.reset();
    dbglog(m_log, "Done");

    m_check_proxy.reset();

    dbglog(m_log, "Destroyed");
}

struct DohUpstream::SocketHandle {
    curl_socket_t fd = CURLM_BAD_SOCKET;
    int action = 0;
    UvPtr<uv_poll_t> poll_handle = nullptr;

    ~SocketHandle() {
        this->poll_handle.reset();
    }

    void init(curl_socket_t sock, int act, DohUpstream *upstream) {
        int what = ((act & CURL_POLL_IN) ? UV_READABLE : 0) | ((act & CURL_POLL_OUT) ? UV_WRITABLE : 0);

        // clang-format off
        int socktype;
        ev_socklen_t socktype_len = sizeof(socktype);
        if (0 == getsockopt(sock, SOL_SOCKET, SO_TYPE,
#ifdef _WIN32
                (char *) &socktype,
#else
                &socktype,
#endif
                &socktype_len) && socktype == SOCK_DGRAM) {
            // Don't poll write on UDP sockets. It burns CPU cycles, while cURL doesn't even really need it.
            what &= ~UV_WRITABLE;
        }
        // clang-format on

        this->fd = sock;
        this->action = act;
        this->poll_handle = Uv<uv_poll_t>::create_with_parent(upstream);
        uv_poll_init_socket(upstream->config().loop.handle(), this->poll_handle->raw(), sock);
        uv_poll_start(this->poll_handle->raw(), what, DohUpstream::on_poll_event);
    }
};

int DohUpstream::on_pool_timer_event(CURLM *multi, long timeout_ms, DohUpstream *upstream) {
    tracelog(upstream->m_log, "{}: Setting timeout to {}ms", __func__, timeout_ms);

    UvPtr<uv_timer_t> &timer = upstream->m_pool.timer;
    if (!timer) {
        timer = Uv<uv_timer_t>::create_with_parent(upstream);
        uv_timer_init(upstream->config().loop.handle(), timer->raw());
    }
    if (timeout_ms < 0) {
        uv_timer_stop(timer->raw());
    } else {
        uv_timer_start(timer->raw(), on_timeout, timeout_ms, 0);
    }
    return 0;
}

void DohUpstream::read_messages() {
    CURLM *pool = m_pool.handle.get();
    int queued;
    CURLMsg *message;

    std::weak_ptr<bool> guard = m_shutdown_guard;
    while (!guard.expired() && nullptr != (message = curl_multi_info_read(pool, &queued))) {
        if (message->msg != CURLMSG_DONE) {
            continue;
        }

        QueryHandle *handle;
        curl_easy_getinfo(message->easy_handle, CURLINFO_PRIVATE, &handle);
        assert(message->easy_handle == handle->curl_handle.get());

        if (message->data.result == CURLE_OK) {
            tracelog_id(handle, "Got response {}", (void *) message->easy_handle);

            long response_code;
            curl_easy_getinfo(message->easy_handle, CURLINFO_RESPONSE_CODE, &response_code);
            if (response_code < 200 || response_code >= 300) {
                handle->error =
                        make_error(DnsError::AE_BAD_RESPONSE, AG_FMT("Got bad response status: {}", response_code));
            }
            char *content_type = nullptr;
            curl_easy_getinfo(message->easy_handle, CURLINFO_CONTENT_TYPE, &content_type);
            if (content_type == nullptr || 0 != strcmp(content_type, "application/dns-message")) {
                handle->error = make_error(DnsError::AE_BAD_RESPONSE,
                        AG_FMT("Got bad response content_type: {}", content_type ? content_type : "(null)"));
            }
            if (handle->response.empty()) {
                handle->error = make_error(DnsError::AE_RESPONSE_PACKET_TOO_SHORT);
            }
        } else {
            if (handle->flags.test(QueryHandle::QHF_PROXIED) && message->data.result == CURLE_COULDNT_CONNECT
                    && m_config.socket_factory->is_proxy_available()) {
                if (m_check_proxy != nullptr) {
                    continue;
                }
                m_check_proxy = CheckProxyState::start(this, m_options.timeout);
                if (m_check_proxy != nullptr) {
                    dbglog_id(handle, "Failed to connect through proxy, checking connectivity with proxy server");
                    continue;
                }
            }

            auto curl_err = make_error(message->data.result);
            if (message->data.result == CURLE_OPERATION_TIMEDOUT) {
                handle->error = make_error(DnsError::AE_TIMED_OUT, curl_err);
            } else {
                handle->error = make_error(DnsError::AE_CURL_ERROR, curl_err);
            }
        }

        handle->cleanup_request();

        m_running_queue.erase(
                std::remove(m_running_queue.begin(), m_running_queue.end(), handle), m_running_queue.end());

        handle->complete();
    }
}

void DohUpstream::on_poll_event(uv_poll_t *poll_handle, int status, int events) {
    DohUpstream *upstream = (DohUpstream *) Uv<uv_poll_t>::parent_from_data(poll_handle->data);
    if (!upstream) {
        return;
    }
    PoolDescriptor &pool = upstream->m_pool;
    int action = ((events & UV_READABLE) ? CURL_CSELECT_IN : 0) | ((events & UV_WRITABLE) ? CURL_CSELECT_OUT : 0);

    int still_running;
    uv_os_fd_t fd;
    uv_fileno((uv_handle_t *) poll_handle, &fd);
    CURLMcode err = curl_multi_socket_action(pool.handle.get(), (curl_socket_t) fd, action, &still_running);
    if (err != CURLM_OK) {
        upstream->stop_all_with_error(make_error(DnsError::AE_CURL_ERROR, make_error(err)));
        return;
    }

    upstream->read_messages();
}

void DohUpstream::on_timeout(uv_timer_t *timer) {
    DohUpstream *upstream = (DohUpstream *) Uv<uv_timer_t>::parent_from_data(timer->data);
    if (!upstream) {
        return;
    }
    PoolDescriptor &pool = upstream->m_pool;

    int still_running;
    CURLMcode err = curl_multi_socket_action(pool.handle.get(), CURL_SOCKET_TIMEOUT, 0, &still_running);
    if (err != CURLM_OK) {
        upstream->stop_all_with_error(make_error(DnsError::AE_CURL_ERROR, make_error(err)));
        return;
    }

    upstream->read_messages();
}

void DohUpstream::add_socket(curl_socket_t socket, int action) {
    SocketHandle *handle = new SocketHandle();
    handle->init(socket, action, this);
    curl_multi_assign(m_pool.handle.get(), socket, handle);
    tracelog(m_log, "New socket: {}", (void *) handle);
}

int DohUpstream::on_socket_update(
        CURL *handle, curl_socket_t socket, int what, DohUpstream *upstream, SocketHandle *socket_data) {
    static constexpr std::string_view WHAT_STR[] = {"none", "IN", "OUT", "INOUT", "REMOVE"};
    tracelog(upstream->m_log, "Socket callback: sock={} curl={} sockh={} what={}", socket, handle, (void *) socket_data,
            WHAT_STR[what]);

    if (what == CURL_POLL_REMOVE) {
        tracelog(upstream->m_log, "Removing socket");
        delete socket_data;
        curl_multi_assign(upstream->m_pool.handle.get(), socket, nullptr);
    } else {
        if (socket_data == nullptr) {
            tracelog(upstream->m_log, "Adding data: {}", WHAT_STR[what]);
            upstream->add_socket(socket, what);
        } else {
            tracelog(upstream->m_log, "Changing action from {} to {}", WHAT_STR[socket_data->action], WHAT_STR[what]);
            socket_data->init(socket, what, upstream);
        }
    }
    return 0;
}

auto DohUpstream::submit_request(QueryHandle *handle) {
    struct Awaitable {
        DohUpstream *self;
        QueryHandle *handle;

        bool await_ready() {
            self->start_request(handle, false);
            return handle->completed;
        }

        void await_suspend(std::coroutine_handle<> h) {
            handle->caller = h;
        }

        void await_resume() {
        }
    };
    tracelog_id(handle, "Submitting request");
    return Awaitable{.self = this, .handle = handle};
};

void DohUpstream::start_request(QueryHandle *handle, bool ignore_proxy) {
    handle->curl_handle = handle->create_curl_handle();
    if (handle->curl_handle == nullptr) {
        // error is already set in `create_curl_handle`
        handle->complete();
        return;
    }

    if (!ignore_proxy && m_config.socket_factory->should_route_through_proxy(utils::TP_TCP)) {
        if (m_check_proxy != nullptr) {
            // will proceed after the proxy check
            goto register_handle;
        }

        if (!handle->set_up_proxy(m_config.socket_factory->get_outbound_proxy_settings())) {
            // error is already set in `set_up_proxy`
            handle->complete();
            return;
        }
        handle->flags.set(QueryHandle::QHF_PROXIED);
    } else {
        handle->flags.reset(QueryHandle::QHF_PROXIED);
    }

    if (CURLMcode e = curl_multi_add_handle(m_pool.handle.get(), handle->curl_handle.get()); e != CURLM_OK) {
        handle->error = make_error(DnsError::AE_CURL_ERROR, "Failed to add request in pool", make_error(e));
        handle->complete();
        return;
    }

register_handle:
    m_running_queue.emplace_back(handle);
}

void DohUpstream::stop_all_with_error(Error<DnsError> e) {
    std::deque<QueryHandle *> queue;
    std::swap(queue, m_running_queue);
    for (auto i = queue.begin(); i != queue.end();) {
        QueryHandle *handle = *i;
        handle->error = e;
        handle->cleanup_request();
        i = queue.erase(i);
        handle->complete();
    }
}

void DohUpstream::retry_pending_queries_directly() {
    std::deque<QueryHandle *> queue;
    queue.swap(m_running_queue);

    for (QueryHandle *h : queue) {
        this->start_request(h, true);
        h->flags.set(QueryHandle::QHF_BYPASSED_PROXY);
    }
}

void DohUpstream::reset_bypassed_proxy_queries() {
    for (auto i = m_running_queue.begin(); i != m_running_queue.end();) {
        QueryHandle *handle = *i;
        if (!handle->flags.test(QueryHandle::QHF_BYPASSED_PROXY)) {
            ++i;
            continue;
        }

        handle->error = make_error(DnsError::AE_OUTBOUND_PROXY_ERROR, "Reset re-routed directly connection");
        handle->cleanup_request();
        i = m_running_queue.erase(i);
        handle->complete();
    }
}

coro::Task<Upstream::ExchangeResult> DohUpstream::exchange(ldns_pkt *request, const DnsMessageInfo *) {

    Millis timeout = m_options.timeout;

    std::weak_ptr<bool> guard = m_shutdown_guard;
    if (m_resolved == nullptr) {
        Bootstrapper::ResolveResult resolve_result = co_await m_bootstrapper->get();
        if (guard.expired()) {
            co_return make_error(DnsError::AE_SHUTTING_DOWN);
        }
        if (resolve_result.error) {
            co_return make_error(DnsError::AE_BOOTSTRAP_ERROR, resolve_result.error);
        }
        assert(!resolve_result.addresses.empty());

        Millis resolve_time = duration_cast<Millis>(resolve_result.time_elapsed);
        if (m_options.timeout < resolve_time) {
            co_return make_error(DnsError::AE_TIMED_OUT,
                    AG_FMT("DNS server name resolving took too much time: {}us", resolve_result.time_elapsed.count()));
        }
        timeout = m_options.timeout - resolve_time;

        std::string entry;
        for (const SocketAddress &address : resolve_result.addresses) {
            assert(address.valid());

            std::string addr = address.str();
            tracelog(m_log, "Server address: {}", addr);

            auto split_result = utils::split_host_port(addr);
            if (split_result.has_error()) {
                co_return make_error(DnsError::AE_INTERNAL_ERROR, split_result.error());
            }
            auto [ip, port] = split_result.value();
            std::string_view host = get_host_name(m_options.address).value();
            if (entry.empty()) {
                entry = AG_FMT("{}:{}:{}", host, port, ip);
            } else {
                entry = AG_FMT("{},{}", entry, ip);
            }
        }
        m_resolved = curl_slist_ptr(curl_slist_append(nullptr, entry.c_str()));
        tracelog(m_log, "Resolved server for curl: {}", entry);
    }

    std::unique_ptr<QueryHandle> handle = create_handle(request, timeout);
    if (handle == nullptr) {
        co_return make_error(DnsError::AE_INTERNAL_ERROR, "Failed to create request handle");
    }

    tracelog_id(handle, "Started");

    Error<DnsError> err;
    ldns_pkt *response = nullptr;
    co_await handle->upstream->submit_request(handle.get());
    if (guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }

    if (handle->error) {
        err = handle->error;
    } else if (ldns_status status = ldns_wire2pkt(&response, handle->response.data(), handle->response.size());
               status != LDNS_STATUS_OK) {
        err = make_error(DnsError::AE_DECODE_ERROR, ldns_get_errorstr_by_id(status));
    }

    handle->restore_packet_id(request);
    if (response != nullptr) {
        handle->restore_packet_id(response);
    }

    tracelog_id(handle, "Completed");

    if (err) {
        co_return err;
    } else {
        co_return ldns_pkt_ptr{response};
    }
}

} // namespace dns

// clang format off
template <>
struct ErrorCodeToString<CURLcode> {
    std::string operator()(CURLcode e) {
        const char *msg = curl_easy_strerror(e);
        return msg ? msg : AG_FMT("Unknown error: {}", (int) e);
    }
};

template <>
struct ErrorCodeToString<CURLMcode> {
    std::string operator()(CURLMcode e) {
        const char *msg = curl_multi_strerror(e);
        return msg ? msg : AG_FMT("Unknown error: {}", (int) e);
    }
};
template <>
struct ErrorCodeToString<CURLSHcode> {
    std::string operator()(CURLSHcode e) {
        const char *msg = curl_share_strerror(e);
        return msg ? msg : AG_FMT("Unknown error: {}", (int) e);
    }
};
// clang format on

} // namespace ag
