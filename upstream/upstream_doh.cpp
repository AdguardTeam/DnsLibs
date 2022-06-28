#include <algorithm>
#include <bitset>
#include <cassert>
#include <cinttypes>

#include "common/defs.h"
#include "common/time_utils.h"
#include "common/utils.h"
#include "net/socket.h"
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
    ErrString error;
    ldns_buffer_ptr request = nullptr;
    Uint8Vector response;
    std::promise<void> barrier;
    std::promise<void> submit_barrier;
    std::bitset<magic_enum::enum_count<Flag>()> flags;

    CURL_ptr create_curl_handle();
    bool set_up_proxy(const OutboundProxySettings *settings);
    void cleanup_request();
    void restore_packet_id(ldns_pkt *packet) const {
        ldns_pkt_set_id(packet, this->request_id);
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
        std::optional<Socket::Error> error = self->socket->connect({
                upstream->m_worker.loop.get(),
                SocketAddress(oproxy_settings->address, oproxy_settings->port),
                {on_connected, nullptr, on_close, self.get()},
                timeout,
        });

        if (error.has_value()) {
            dbglog(upstream->m_log, "Failed to check connectivity with proxy: {} ({})", error->description,
                    error->code);
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

    static void on_close(void *arg, std::optional<Socket::Error> error) {
        auto *self = (CheckProxyState *) arg;
        DohUpstream *upstream = self->upstream;

        SocketFactory *factory = upstream->m_config.socket_factory;
        SocketFactory::ProxyConectionFailedResult result = factory->on_proxy_connection_failed(
                error.has_value() ? std::make_optional(error->code) : std::nullopt);

        upstream->m_check_proxy.reset();

        switch (result) {
        case SocketFactory::SFPCFR_CLOSE_CONNECTION:
            upstream->stop_all_with_error("Couldn't connect to proxy server");
            break;
        case SocketFactory::SFPCFR_RETRY_DIRECTLY:
            upstream->retry_pending_queries_directly();
            upstream->m_reset_bypassed_proxy_connections_subscribe_id
                    = factory->subscribe_to_reset_bypassed_proxy_connections_event({[](void *arg) {
                          auto *self = (DohUpstream *) arg;
                          std::scoped_lock l(self->m_guard);
                          self->m_worker.loop->submit([self]() {
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
        warnlog(self->m_log, "Failed to bind socket to interface: {}", *error);
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
        this->error = "Failed to init curl handle";
        return nullptr;
    }

    DohUpstream *upstream = this->upstream;
    ldns_buffer *raw_request = this->request.get();
    uint64_t timeout = upstream->m_options.timeout.count();
    CURL *curl = curl_ptr.get();
    if (CURLcode e; CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_URL, upstream->m_options.address.data()))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, true))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeout))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_WRITEDATA, this))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_USERAGENT, nullptr))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ldns_buffer_at(raw_request, 0)))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, ldns_buffer_position(raw_request)))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, upstream->m_request_headers.get()))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_PRIVATE, this))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, DohUpstream::ssl_callback))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, this))
            || CURLE_OK
                    != (e = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,
                                false)) // We verify ourselves, see DohUpstream::ssl_callback
            || CURLE_OK
                    != (e = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,
                                false)) // We verify ourselves, see DohUpstream::ssl_callback
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, true))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, curl_opensocket))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, upstream))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, verbose_callback))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_DEBUGDATA, this))
            || CURLE_OK
                    != (e = curl_easy_setopt(
                                curl, CURLOPT_VERBOSE, (long) (log->is_enabled(LogLevel::LOG_LEVEL_DEBUG))))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SHARE, get_curl_share()))
            || (upstream->m_resolved != nullptr
                    && CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_RESOLVE, upstream->m_resolved.get())))) {
        this->error = AG_FMT("Failed to set options on curl handle: {} (id={})", curl_easy_strerror(e), e);
        return nullptr;
    }

    return curl_ptr;
}

bool DohUpstream::QueryHandle::set_up_proxy(const OutboundProxySettings *settings) {
    static constexpr curl_proxytype AG_TO_CURL_PROXY_PROTOCOL[magic_enum::enum_count<OutboundProxyProtocol>()] = {
            [(int) OutboundProxyProtocol::HTTP_CONNECT] = CURLPROXY_HTTP,
            [(int) OutboundProxyProtocol::HTTPS_CONNECT] = CURLPROXY_HTTPS,
            [(int) OutboundProxyProtocol::SOCKS4] = CURLPROXY_SOCKS4,
            [(int) OutboundProxyProtocol::SOCKS5] = CURLPROXY_SOCKS5,
            [(int) OutboundProxyProtocol::SOCKS5_UDP] = CURLPROXY_SOCKS5,
    };

    CURL *curl = this->curl_handle.get();

#define SETOPT_S(curl_, opt_, val_)                                                                                    \
    do {                                                                                                               \
        if (CURLcode e = curl_easy_setopt((curl_), (opt_), (val_)); e != CURLE_OK) {                                   \
            this->error = AG_FMT("Failed to set option {} on curl handle: {} ({})", opt_, curl_easy_strerror(e), e);   \
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
        CURLMcode perr [[maybe_unused]]
        = curl_multi_remove_handle(this->upstream->m_pool.handle.get(), this->curl_handle.get());
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
    std::string_view host = url;
    host.remove_prefix(DohUpstream::SCHEME.length());
    host = host.substr(0, host.find('/'));
    return host;
}

static std::string_view get_host_name(std::string_view url) {
    return utils::split_host_port(get_host_port(url)).first;
}

int DohUpstream::verify_callback(X509_STORE_CTX *ctx, void *arg) {
    DohUpstream::QueryHandle *handle = (DohUpstream::QueryHandle *) arg;
    DohUpstream *upstream = handle->upstream;

    SSL *ssl = (SSL *) X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    tracelog_id(handle, "{}(): SNI={}", __func__, (sni == nullptr) ? "null" : sni);

    if (const OutboundProxySettings *proxy_settings = upstream->m_config.socket_factory->get_outbound_proxy_settings();
            proxy_settings != nullptr && proxy_settings->protocol == OutboundProxyProtocol::HTTPS_CONNECT
            && proxy_settings->trust_any_certificate
            && (sni == nullptr || sni != get_host_name(upstream->m_options.address))) {
        tracelog_id(handle, "Trusting any proxy certificate as specified in settings");
        return 1;
    }

    const CertificateVerifier *verifier = upstream->m_config.socket_factory->get_certificate_verifier();
    if (verifier == nullptr) {
        std::string err = "Cannot verify certificate due to verifier is not set";
        dbglog_id(handle, "{}", err);
        handle->error = std::move(err);
        return 0;
    }

    if (ErrString err = verifier->verify(ctx, get_host_name(upstream->m_options.address)); err.has_value()) {
        dbglog_id(handle, "Failed to verify certificate: {}", err.value());
        handle->error = std::move(err);
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

static curl_slist_ptr create_resolved_hosts_list(std::string_view url, const IpAddress &addr) {
    if (std::holds_alternative<std::monostate>(addr)) {
        return nullptr;
    }

    std::string_view host_port = get_host_port(url);
    auto [host, port_str] = utils::split_host_port(host_port);
    uint16_t port = ag::utils::to_integer<uint16_t>(port_str).value_or(ag::DEFAULT_DOH_PORT);

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

ErrString DohUpstream::init() {
    m_resolved = create_resolved_hosts_list(m_options.address, m_options.resolved_server_ip);

    curl_slist *headers;
    if (nullptr == (headers = curl_slist_append(nullptr, "Content-Type: application/dns-message"))
            || nullptr == (headers = curl_slist_append(headers, "Accept: application/dns-message"))) {
        std::string err = "Failed to create http headers for request";
        errlog(m_log, "{}", err);
        return err;
    }
    m_request_headers.reset(headers);

    m_pool.handle = create_pool();
    if (m_pool.handle == nullptr) {
        return "Failed to create CURL handle pool";
    }

    if (m_resolved == nullptr) {
        if (!m_options.bootstrap.empty() || SocketAddress(get_host_name(m_options.address), 0).valid()) {
            BootstrapperPtr bootstrapper = std::make_unique<Bootstrapper>(
                    Bootstrapper::Params{get_host_port(m_options.address), DEFAULT_DOH_PORT,
                            m_options.bootstrap, m_options.timeout, m_config, m_options.outbound_interface});
            if (ErrString err = bootstrapper->init(); !err.has_value()) {
                m_bootstrapper = std::move(bootstrapper);
            } else {
                std::string err_message = AG_FMT("Failed to create bootstrapper: {}", err.value());
                errlog(m_log, "{}", err_message);
                return err_message;
            }
        } else {
            constexpr std::string_view err
                    = "At least one the following should be true: server address is specified, url contains valid "
                      "server address as a host name, bootstrap server is specified";
            errlog(m_log, "{}", err);
            return std::string(err);
        }
    }

    return std::nullopt;
}

DohUpstream::~DohUpstream() {
    infolog(m_log, "Destroying...");

    {
        std::unique_lock lock(m_guard);
        if (auto id = m_reset_bypassed_proxy_connections_subscribe_id; id.has_value()) {
            m_config.socket_factory->unsubscribe_from_reset_bypassed_proxy_connections_event(id.value());
        }
    }

    infolog(m_log, "Stopping event loop...");
    m_worker.loop->submit([this]() {
        this->stop_all_with_error("Upstream has been stopped");
    });
    // Delete the event before deleting the loop
    m_pool.timer_event.reset();
    // Stop and join before reset() are NOT redundant, because
    // `loop->reset()` sets `loop` to nullptr before calling the destructor
    m_worker.loop->stop();
    m_worker.loop->join();
    m_worker.loop.reset();
    infolog(m_log, "Done");

    infolog(m_log, "Waiting all requests completed...");
    {
        std::unique_lock lock(m_guard);
        m_worker.no_requests_condition.wait(lock, [this]() -> bool {
            return m_worker.requests_counter == 0;
        });
    }
    infolog(m_log, "Done");

    // Defy stray `QueryHandle`s not defied on the event loop
    this->defy_requests();

    m_check_proxy.reset();

    infolog(m_log, "Destroyed");
}

struct DohUpstream::SocketHandle {
    curl_socket_t fd = CURLM_BAD_SOCKET;
    int action = 0;
    event_ptr event_handle = nullptr;

    ~SocketHandle() {
        this->event_handle.reset();
    }

    void init(curl_socket_t socket, int act, DohUpstream *upstream) {
        int what = ((act & CURL_POLL_IN) ? EV_READ : 0) | ((act & CURL_POLL_OUT) ? EV_WRITE : 0) | EV_PERSIST;

        this->fd = socket;
        this->action = act;
        this->event_handle.reset(
                event_new(upstream->m_worker.loop->c_base(), socket, what, DohUpstream::on_socket_event, upstream));
        event_add(this->event_handle.get(), nullptr);
    }
};

int DohUpstream::on_pool_timer_event(CURLM *multi, long timeout_ms, DohUpstream *upstream) {
    tracelog(upstream->m_log, "{}: Setting timeout to {}ms", __func__, timeout_ms);

    event_ptr &event = upstream->m_pool.timer_event;
    if (timeout_ms < 0) {
        event.reset();
    } else {
        event.reset(event_new(upstream->m_worker.loop->c_base(), 0, EV_TIMEOUT, on_event_timeout, upstream));
        timeval timeout = duration_to_timeval(Millis(timeout_ms));
        evtimer_add(event.get(), &timeout);
    }
    return 0;
}

void DohUpstream::read_messages() {
    CURLM *pool = m_pool.handle.get();
    int queued;
    CURLMsg *message;

    while (nullptr != (message = curl_multi_info_read(pool, &queued))) {
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
                handle->error = AG_FMT("Got bad response status: {}", response_code);
            }
            char *content_type = nullptr;
            curl_easy_getinfo(message->easy_handle, CURLINFO_CONTENT_TYPE, &content_type);
            if (content_type == nullptr || 0 != strcmp(content_type, "application/dns-message")) {
                handle->error = AG_FMT("Got bad response content_type: {}", content_type ? content_type : "(null)");
            }
            if (handle->response.empty()) {
                handle->error = "Got empty response";
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

            if (message->data.result == CURLE_OPERATION_TIMEDOUT) {
                handle->error = TIMEOUT_STR;
            } else {
                handle->error = AG_FMT("Failed to perform request: {}", curl_easy_strerror(message->data.result));
            }
        }

        handle->cleanup_request();

        std::deque<QueryHandle *> &queue = m_worker.running_queue;
        queue.erase(std::remove(queue.begin(), queue.end(), handle), queue.end());

        handle->barrier.set_value();
    }
}

void DohUpstream::on_socket_event(evutil_socket_t fd, short kind, void *arg) {
    DohUpstream *upstream = (DohUpstream *) arg;
    PoolDescriptor &pool = upstream->m_pool;
    int action = ((kind & EV_READ) ? CURL_CSELECT_IN : 0) | ((kind & EV_WRITE) ? CURL_CSELECT_OUT : 0);

    int still_running;
    CURLMcode err = curl_multi_socket_action(pool.handle.get(), fd, action, &still_running);
    if (err != CURLM_OK) {
        upstream->stop_all_with_error(curl_multi_strerror(err));
        return;
    }

    upstream->read_messages();
}

void DohUpstream::on_event_timeout(evutil_socket_t fd, short kind, void *arg) {
    DohUpstream *upstream = (DohUpstream *) arg;
    PoolDescriptor &pool = upstream->m_pool;

    int still_running;
    CURLMcode err = curl_multi_socket_action(pool.handle.get(), CURL_SOCKET_TIMEOUT, 0, &still_running);
    if (err != CURLM_OK) {
        upstream->stop_all_with_error(curl_multi_strerror(err));
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

void DohUpstream::submit_request(QueryHandle *handle) {
    tracelog_id(handle, "Submitting request");
    this->start_request(handle, false);
    handle->submit_barrier.set_value();
}

void DohUpstream::start_request(QueryHandle *handle, bool ignore_proxy) {
    handle->curl_handle = handle->create_curl_handle();
    if (handle->curl_handle == nullptr) {
        // error is already set in `create_curl_handle`
        handle->barrier.set_value();
        return;
    }

    if (!ignore_proxy && m_config.socket_factory->should_route_through_proxy(utils::TP_TCP)) {
        if (m_check_proxy != nullptr) {
            // will proceed after the proxy check
            goto register_handle;
        }

        if (!handle->set_up_proxy(m_config.socket_factory->get_outbound_proxy_settings())) {
            // error is already set in `set_up_proxy`
            handle->barrier.set_value();
            return;
        }
        handle->flags.set(QueryHandle::QHF_PROXIED);
    } else {
        handle->flags.reset(QueryHandle::QHF_PROXIED);
    }

    if (CURLMcode e = curl_multi_add_handle(m_pool.handle.get(), handle->curl_handle.get()); e != CURLM_OK) {
        handle->error = AG_FMT("Failed to add request in pool: {}", curl_multi_strerror(e));
        handle->barrier.set_value();
        return;
    }

register_handle:
    m_worker.running_queue.emplace_back(handle);
}

void DohUpstream::defy_requests() {
    std::list<std::unique_ptr<QueryHandle>> handle_ptrs;

    m_guard.lock();
    handle_ptrs.swap(m_defied_handles);
    m_guard.unlock();

    for (auto &ptr : handle_ptrs) {
        QueryHandle *handle = ptr.get();
        tracelog_id(handle, "Defying request");

        handle->cleanup_request();

        std::deque<QueryHandle *> &queue = m_worker.running_queue;
        queue.erase(std::remove(queue.begin(), queue.end(), handle), queue.end());
    }
}

void DohUpstream::stop_all_with_error(const ErrString &e) {
    std::deque<QueryHandle *> &queue = m_worker.running_queue;
    for (auto i = queue.begin(); i != queue.end();) {
        QueryHandle *handle = *i;
        handle->error = e;
        handle->cleanup_request();
        i = queue.erase(i);
        handle->barrier.set_value();
    }
}

void DohUpstream::retry_pending_queries_directly() {
    std::deque<QueryHandle *> queue;
    queue.swap(m_worker.running_queue);

    for (QueryHandle *h : queue) {
        this->start_request(h, true);
        h->flags.set(QueryHandle::QHF_BYPASSED_PROXY);
    }
}

void DohUpstream::reset_bypassed_proxy_queries() {
    std::deque<QueryHandle *> &queue = m_worker.running_queue;
    for (auto i = queue.begin(); i != queue.end();) {
        QueryHandle *handle = *i;
        if (!handle->flags.test(QueryHandle::QHF_BYPASSED_PROXY)) {
            ++i;
            continue;
        }

        handle->error = "Reset re-routed directly connection";
        handle->cleanup_request();
        i = queue.erase(i);
        handle->barrier.set_value();
    }
}

DohUpstream::ExchangeResult DohUpstream::exchange(ldns_pkt *request, const DnsMessageInfo *) {
    // register request
    m_guard.lock();
    ++m_worker.requests_counter;
    m_guard.unlock();

    // unregister request at exit for safe destruction
    utils::ScopeExit request_unregister([this]() {
        std::scoped_lock lock(m_guard);
        if (0 == --m_worker.requests_counter) {
            m_worker.no_requests_condition.notify_one();
        }
    });

    Millis timeout = m_options.timeout;

    if (std::unique_lock guard(m_guard); m_resolved == nullptr) {
        Bootstrapper::ResolveResult resolve_result = m_bootstrapper->get();
        if (resolve_result.error.has_value()) {
            return {nullptr, std::move(resolve_result.error)};
        }
        assert(!resolve_result.addresses.empty());

        Millis resolve_time = duration_cast<Millis>(resolve_result.time_elapsed);
        if (m_options.timeout < resolve_time) {
            return {nullptr,
                    AG_FMT("DNS server name resolving took too much time: {}us", resolve_result.time_elapsed.count())};
        }
        timeout = m_options.timeout - resolve_time;

        std::string entry;
        for (const SocketAddress &address : resolve_result.addresses) {
            assert(address.valid());

            std::string addr = address.str();
            tracelog(m_log, "Server address: {}", addr);

            auto [ip, port] = utils::split_host_port(addr);
            std::string_view host = get_host_name(m_options.address);
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
        return {nullptr, "Failed to create request handle"};
    }

    tracelog_id(handle, "Started");

    std::future<void> request_completed = handle->barrier.get_future();
    std::future<void> request_submitted = handle->submit_barrier.get_future();
    m_worker.loop->submit([h = handle.get()]() {
        h->upstream->submit_request(h);
    });

    ErrString err;
    ldns_pkt *response = nullptr;
    bool timed_out = false;
    if (std::future_status status = request_completed.wait_for(timeout); status != std::future_status::ready) {
        err = TIMEOUT_STR;
        timed_out = true;
    } else if (handle->error.has_value()) {
        err = std::move(handle->error);
    } else if (ldns_status status = ldns_wire2pkt(&response, handle->response.data(), handle->response.size());
               status != LDNS_STATUS_OK) {
        err = AG_FMT("Failed to parse response: {}", ldns_get_errorstr_by_id(status));
    }

    handle->restore_packet_id(request);
    if (response != nullptr) {
        handle->restore_packet_id(response);
    }

    if (!timed_out) {
        tracelog_id(handle, "Completed");
    } else {
        tracelog_id(handle, "Request timed out");

        /* Wait until `submit_request` is done with the handle before scheduling it for deletion.
         * Explanation:
         *   `request_completed.wait_for()` could have timed out because the whole process
         *   was suspended for a few seconds. In that case, `submit_request` might not yet
         *   have been executed on the event loop thread, and if we immediately schedule
         *   the handle to be cleaned up, `submit_request` will eventually execute and
         *   access the deleted pointer.
         */
        request_submitted.wait();

        std::scoped_lock l(m_guard);
        m_defied_handles.emplace_back(std::move(handle));
        if (m_defied_handles.size() == 1) {
            m_worker.loop->submit([this]() {
                this->defy_requests();
            });
        }
    }

    return {ldns_pkt_ptr(response), std::move(err)};
}

} // namespace ag
