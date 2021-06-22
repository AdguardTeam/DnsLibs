#include <cinttypes>
#include <cassert>
#include <algorithm>

#include <ag_utils.h>
#include <ag_defs.h>
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


using namespace ag;
using namespace std::chrono;


struct initializer {
    initializer() {
        curl_global_init(CURL_GLOBAL_ALL);
    }
    ~initializer() {
        curl_global_cleanup();
    }
};


static constexpr std::string_view USER_AGENT = "ag-dns";


struct dns_over_https::query_handle {
    using CURL_ptr = std::unique_ptr<CURL, ftor<&curl_easy_cleanup>>;

    const logger *log = nullptr;
    dns_over_https *upstream = nullptr;
    size_t request_id = 0;
    CURL_ptr curl_handle;
    err_string error;
    ldns_buffer_ptr request = nullptr;
    std::vector<uint8_t> response;
    std::promise<void> barrier;
    std::promise<void> submit_barrier;

    CURL_ptr create_curl_handle();
    bool set_up_proxy(const outbound_proxy_settings *settings);
    void cleanup_request();
    void restore_packet_id(ldns_pkt *packet) const {
        ldns_pkt_set_id(packet, this->request_id);
    }
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *arg) {
    dns_over_https::query_handle *h = (dns_over_https::query_handle *)arg;
    size_t full_size = size * nmemb;
    h->response.insert(h->response.end(), (uint8_t *)contents, (uint8_t *)contents + full_size);
    return full_size;
}

curl_socket_t dns_over_https::curl_opensocket(void *clientp, curlsocktype, struct curl_sockaddr *address) {
    auto *self = (ag::dns_over_https *) clientp;
    curl_socket_t curlfd = ::socket(address->family, address->socktype, address->protocol);
    if (curlfd == CURL_SOCKET_BAD) {
        return CURL_SOCKET_BAD;
    }
    ag::socket_address addr{&address->addr};
    if (auto error = self->m_config.socket_factory->prepare_fd(curlfd, addr, self->m_options.outbound_interface)) {
        warnlog(self->log, "Failed to bind socket to interface: {}", *error);
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
    static std::unique_ptr<CURLSH, ag::ftor<&curl_share_cleanup>> curl_share(init_curl_share());
    return curl_share.get();
}

dns_over_https::query_handle::CURL_ptr dns_over_https::query_handle::create_curl_handle() {
    CURL_ptr curl_ptr{ curl_easy_init() };
    if (curl_ptr == nullptr) {
        this->error = "Failed to init curl handle";
        return nullptr;
    }

    dns_over_https *upstream = this->upstream;
    ldns_buffer *raw_request = this->request.get();
    uint64_t timeout = upstream->m_options.timeout.count();
    CURL *curl = curl_ptr.get();
    if (CURLcode e;
            CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_URL, upstream->m_options.address.data()))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, true))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeout))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_WRITEDATA, this))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT.data()))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ldns_buffer_at(raw_request, 0)))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, ldns_buffer_position(raw_request)))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, upstream->request_headers.get()))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_PRIVATE, this))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, dns_over_https::ssl_callback))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, this))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false)) // We verify ourselves, see dns_over_https::ssl_callback
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false)) // We verify ourselves, see dns_over_https::ssl_callback
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, true))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, curl_opensocket))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, upstream))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SHARE, get_curl_share()))
            || (upstream->resolved != nullptr
                && CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_RESOLVE, upstream->resolved.get())))) {
        this->error = AG_FMT("Failed to set options on curl handle: {} (id={})",
            curl_easy_strerror(e), e);
        return nullptr;
    }

    return curl_ptr;
}

bool dns_over_https::query_handle::set_up_proxy(const outbound_proxy_settings *settings) {
    static constexpr curl_proxytype AG_TO_CURL_PROXY_PROTOCOL[] = {
            [(int)outbound_proxy_protocol::HTTP_CONNECT] = CURLPROXY_HTTP,
            [(int)outbound_proxy_protocol::HTTPS_CONNECT] = CURLPROXY_HTTPS,
            [(int)outbound_proxy_protocol::SOCKS4] = CURLPROXY_SOCKS4,
            [(int)outbound_proxy_protocol::SOCKS5] = CURLPROXY_SOCKS5,
            [(int)outbound_proxy_protocol::SOCKS5_UDP] = CURLPROXY_SOCKS5,
    };

    CURL *curl = this->curl_handle.get();

#define SETOPT_S(curl_, opt_, val_) \
    do { \
        if (CURLcode e = curl_easy_setopt((curl_), (opt_), (val_)); \
                e != CURLE_OK) { \
            this->error = AG_FMT("Failed to set option {} on curl handle: {} ({})", \
                    magic_enum::enum_name(opt_), curl_easy_strerror(e), e); \
            return false; \
        } \
    } while (0)

    SETOPT_S(curl, CURLOPT_PROXYTYPE, AG_TO_CURL_PROXY_PROTOCOL[(int)settings->protocol]);
    SETOPT_S(curl, CURLOPT_PROXY, settings->address.c_str());
    SETOPT_S(curl, CURLOPT_PROXYPORT, settings->port);

    if (const auto &auth_info = settings->auth_info; auth_info.has_value()) {
        SETOPT_S(curl, CURLOPT_PROXYUSERNAME, auth_info->username.c_str());
        SETOPT_S(curl, CURLOPT_PROXYPASSWORD, auth_info->password.c_str());
    }

    SETOPT_S(curl, CURLOPT_PROXY_SSL_VERIFYPEER, false); // We verify ourselves, see dns_over_https::ssl_callback
    SETOPT_S(curl, CURLOPT_PROXY_SSL_VERIFYHOST, false); // We verify ourselves, see dns_over_https::ssl_callback

#undef SETOPT_S

    return true;
}

void dns_over_https::query_handle::cleanup_request() {
    if (this->curl_handle) {
        CURLMcode perr [[maybe_unused]] =
                curl_multi_remove_handle(this->upstream->pool.handle.get(), this->curl_handle.get());
        assert(perr == CURLM_OK);
        this->curl_handle.reset();
    }
}

std::unique_ptr<dns_over_https::query_handle> dns_over_https::create_handle(ldns_pkt *request,  milliseconds timeout) const {
    std::unique_ptr<query_handle> h = std::make_unique<query_handle>();
    h->log = &this->log;
    h->upstream = (dns_over_https *)this;
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
    host.remove_prefix(dns_over_https::SCHEME.length());
    host = host.substr(0, host.find('/'));
    return host;
}

static std::string_view get_host_name(std::string_view url) {
    return utils::split_host_port(get_host_port(url)).first;
}

int dns_over_https::verify_callback(X509_STORE_CTX *ctx, void *arg) {
    dns_over_https::query_handle *handle = (dns_over_https::query_handle *)arg;
    dns_over_https *upstream = handle->upstream;

    SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    tracelog_id(handle, "{}(): SNI={}", __func__, (sni == nullptr) ? "null" : sni);

    if (const outbound_proxy_settings *proxy_settings = upstream->m_config.socket_factory->get_outbound_proxy_settings();
            proxy_settings != nullptr
            && proxy_settings->protocol == outbound_proxy_protocol::HTTPS_CONNECT
            && proxy_settings->trust_any_certificate
            && (sni == nullptr || sni != get_host_name(upstream->m_options.address))) {
        tracelog_id(handle, "Trusting any proxy certificate as specified in settings");
        return 1;
    }

    if (upstream->m_config.cert_verifier == nullptr) {
        std::string err = "Cannot verify certificate due to verifier is not set";
        dbglog_id(handle, "{}", err);
        handle->error = std::move(err);
        return 0;
    }

    if (err_string err = upstream->m_config.cert_verifier->verify(ctx, get_host_name(upstream->m_options.address));
            err.has_value()) {
        dbglog_id(handle, "Failed to verify certificate: {}", err.value());
        handle->error = std::move(err);
        return 0;
    }

    tracelog_id(handle, "Verified successfully");
    return 1;
}

CURLcode dns_over_https::ssl_callback(CURL *curl, void *sslctx, void *arg) {
    SSL_CTX *ctx = (SSL_CTX *)sslctx;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_cert_verify_callback(ctx, verify_callback, arg);
    return CURLE_OK;
}

static curl_slist_ptr create_resolved_hosts_list(std::string_view url, const ip_address_variant &addr) {
    if (std::holds_alternative<std::monostate>(addr)) {
        return nullptr;
    }

    std::string_view host_port = get_host_port(url);
    auto [host, port_str] = utils::split_host_port(host_port);
    int port = dns_over_https::DEFAULT_PORT;
    if (int p; !port_str.empty() && 0 != (p = std::strtol(std::string(port_str).c_str(), nullptr, 10))) {
        port = p;
    }

    std::string entry;
    if (const auto *ipv4 = std::get_if<uint8_array<4>>(&addr); ipv4 != nullptr) {
        const auto &ip = *ipv4;
        entry = AG_FMT("{}:{}:{}.{}.{}.{}", host, port, ip[0], ip[1], ip[2], ip[3]);
    } else {
        const auto &ip = std::get<uint8_array<16>>(addr);
        entry = AG_FMT("{}:{}:[{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}]",
            host, port,
            ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
            ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
    }

    return curl_slist_ptr(curl_slist_append(nullptr, entry.c_str()));
}

curl_pool_ptr dns_over_https::create_pool() const {
    CURLM *pool = curl_multi_init();
    if (pool == nullptr) {
        return nullptr;
    }
    curl_pool_ptr pool_holder = curl_pool_ptr(pool);

    if (CURLMcode e;
            CURLM_OK != (e = curl_multi_setopt(pool, CURLMOPT_SOCKETFUNCTION, on_socket_update))
            || CURLM_OK != (e = curl_multi_setopt(pool, CURLMOPT_SOCKETDATA, this))
            || CURLM_OK != (e = curl_multi_setopt(pool, CURLMOPT_TIMERFUNCTION, on_pool_timer_event))
            || CURLM_OK != (e = curl_multi_setopt(pool, CURLMOPT_TIMERDATA, this))
            || CURLM_OK != (e = curl_multi_setopt(pool, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX))) {
        errlog(log, "Failed to set options of curl pool: {} (id={})", curl_multi_strerror(e), e);
        return nullptr;
    }

    return pool_holder;
}

dns_over_https::dns_over_https(const upstream_options &opts, const upstream_factory_config &config)
    : upstream(opts, config)
{
    static const initializer ensure_initialized;
}

err_string dns_over_https::init() {
    this->resolved = create_resolved_hosts_list(this->m_options.address, this->m_options.resolved_server_ip);

    curl_slist *headers;
    if (nullptr == (headers = curl_slist_append(nullptr, "Content-Type: application/dns-message"))
            || nullptr == (headers = curl_slist_append(headers, "Accept: application/dns-message"))) {
        std::string err = "Failed to create http headers for request";
        errlog(log, "{}", err);
        return err;
    }
    this->request_headers.reset(headers);

    this->pool.handle = create_pool();
    if (this->pool.handle == nullptr) {
        return "Failed to create CURL handle pool";
    }

    if (this->resolved == nullptr) {
        if (!this->m_options.bootstrap.empty() || socket_address(get_host_name(this->m_options.address), 0).valid()) {
            bootstrapper_ptr bootstrapper = std::make_unique<ag::bootstrapper>(
                bootstrapper::params{get_host_port(m_options.address), dns_over_https::DEFAULT_PORT,
                                     m_options.bootstrap, m_options.timeout, m_config,
                                     m_options.outbound_interface});
            if (err_string err = bootstrapper->init(); !err.has_value()) {
                this->bootstrapper = std::move(bootstrapper);
            } else {
                std::string err_message = AG_FMT("Failed to create bootstrapper: {}", err.value());
                errlog(log, "{}", err_message);
                return err_message;
            }
        } else {
            constexpr std::string_view err = "At least one the following should be true: server address is specified, url contains valid server address as a host name, bootstrap server is specified";
            errlog(log, "{}", err);
            return std::string(err);
        }
    }

    return std::nullopt;
}

dns_over_https::~dns_over_https() {
    infolog(this->log, "Destroying...");

    infolog(this->log, "Stopping event loop...");
    this->worker.loop->submit([this] () { this->stop_all_with_error("Upstream has been stopped"); });
    // Delete the event before deleting the loop
    this->pool.timer_event.reset();
    // Stop and join before reset() are NOT redundant, because
    // `loop->reset()` sets `loop` to nullptr before calling the destructor
    this->worker.loop->stop();
    this->worker.loop->join();
    this->worker.loop.reset();
    infolog(this->log, "Done");

    infolog(this->log, "Waiting all requests completed...");
    {
        std::unique_lock lock(this->guard);
        this->worker.no_requests_condition.wait(lock,
            [this] () -> bool {
                return this->worker.requests_counter == 0;
            });
    }
    infolog(this->log, "Done");

    // Defy stray `query_handle`s not defied on the event loop
    this->defy_requests();

    infolog(this->log, "Destroyed");
}

struct dns_over_https::socket_handle {
    curl_socket_t fd = CURLM_BAD_SOCKET;
    int action = 0;
    event_ptr event_handle = nullptr;

    ~socket_handle() {
        this->event_handle.reset();
    }

    void init(curl_socket_t socket, int act, dns_over_https *upstream) {
        int what = ((act & CURL_POLL_IN) ? EV_READ : 0)
            | ((act & CURL_POLL_OUT) ? EV_WRITE : 0)
            | EV_PERSIST;

        this->fd = socket;
        this->action = act;
        this->event_handle.reset(event_new(upstream->worker.loop->c_base(), socket, what,
            dns_over_https::on_socket_event, upstream));
        event_add(this->event_handle.get(), nullptr);
    }
};

int dns_over_https::on_pool_timer_event(CURLM *multi, long timeout_ms, dns_over_https *upstream) {
    tracelog(upstream->log, "{}: Setting timeout to {}ms", __func__, timeout_ms);

    event_ptr &event = upstream->pool.timer_event;
    if (timeout_ms < 0) {
        event.reset();
    } else {
        event.reset(event_new(upstream->worker.loop->c_base(), 0, EV_TIMEOUT, on_event_timeout, upstream));
        timeval timeout = utils::duration_to_timeval(milliseconds(timeout_ms));
        evtimer_add(event.get(), &timeout);
    }
    return 0;
}

void dns_over_https::read_messages() {
    CURLM *pool = this->pool.handle.get();
    int queued;
    CURLMsg *message;

    while (nullptr != (message = curl_multi_info_read(pool, &queued))) {
        if (message->msg != CURLMSG_DONE) {
            continue;
        }

        query_handle *handle;
        curl_easy_getinfo(message->easy_handle, CURLINFO_PRIVATE, &handle);
        assert(message->easy_handle == handle->curl_handle.get());

        if (message->data.result != CURLE_OK) {
            handle->error = AG_FMT("Failed to perform request: {}", curl_easy_strerror(message->data.result));
        } else {
            tracelog_id(handle, "Got response {}", (void*)message->easy_handle);

            long response_code;
            curl_easy_getinfo(message->easy_handle, CURLINFO_RESPONSE_CODE, &response_code);
            if (response_code < 200 || response_code >= 300) {
                handle->error = AG_FMT("Got bad response status: {}", response_code);
            }
        }

        handle->cleanup_request();

        std::deque<query_handle *> &queue = this->worker.running_queue;
        queue.erase(std::remove(queue.begin(), queue.end(), handle), queue.end());

        handle->barrier.set_value();
    }
}

void dns_over_https::on_socket_event(evutil_socket_t fd, short kind, void *arg) {
    dns_over_https *upstream = (dns_over_https *)arg;
    pool_descriptor &pool = upstream->pool;
    int action = ((kind & EV_READ) ? CURL_CSELECT_IN : 0)
        | ((kind & EV_WRITE) ? CURL_CSELECT_OUT : 0);

    int still_running;
    CURLMcode err = curl_multi_socket_action(pool.handle.get(), fd, action, &still_running);
    if (err != CURLM_OK) {
        upstream->stop_all_with_error(curl_multi_strerror(err));
        return;
    }

    upstream->read_messages();
}

void dns_over_https::on_event_timeout(evutil_socket_t fd, short kind, void *arg) {
    dns_over_https *upstream = (dns_over_https *)arg;
    pool_descriptor &pool = upstream->pool;

    int still_running;
    CURLMcode err = curl_multi_socket_action(pool.handle.get(), CURL_SOCKET_TIMEOUT, 0, &still_running);
    if (err != CURLM_OK) {
        upstream->stop_all_with_error(curl_multi_strerror(err));
        return;
    }

    upstream->read_messages();
}

void dns_over_https::add_socket(curl_socket_t socket, int action) {
    socket_handle *handle = new socket_handle();
    handle->init(socket, action, this);
    curl_multi_assign(this->pool.handle.get(), socket, handle);
    tracelog(log, "New socket: {}", (void *)handle);
}

int dns_over_https::on_socket_update(CURL *handle, curl_socket_t socket, int what,
        dns_over_https *upstream, socket_handle *socket_data) {
    static constexpr std::string_view WHAT_STR[] = { "none", "IN", "OUT", "INOUT", "REMOVE" };
    tracelog(upstream->log, "Socket callback: sock={} curl={} sockh={} what={}", socket, handle, (void*)socket_data, WHAT_STR[what]);

    if (what == CURL_POLL_REMOVE) {
        tracelog(upstream->log, "Removing socket");
        delete socket_data;
        curl_multi_assign(upstream->pool.handle.get(), socket, nullptr);
    } else {
        if (socket_data == nullptr) {
            tracelog(upstream->log, "Adding data: {}", WHAT_STR[what]);
            upstream->add_socket(socket, what);
        } else {
            tracelog(upstream->log, "Changing action from {} to {}", WHAT_STR[socket_data->action], WHAT_STR[what]);
            socket_data->init(socket, what, upstream);
        }
    }
    return 0;
}

void dns_over_https::submit_request(query_handle *handle) {
    tracelog_id(handle, "Submitting request");

    ag::utils::scope_exit signal_submit_done([&] {
        handle->submit_barrier.set_value();
    });

    handle->curl_handle = handle->create_curl_handle();
    if (handle->curl_handle == nullptr) {
        // error is already set in `create_curl_handle`
        handle->barrier.set_value();
        return;
    }

    if (const outbound_proxy_settings *proxy_settings = this->m_config.socket_factory->get_outbound_proxy_settings();
            proxy_settings != nullptr && !handle->set_up_proxy(proxy_settings)) {
        // error is already set in `set_up_proxy`
        handle->barrier.set_value();
        return;
    }

    if (CURLMcode e = curl_multi_add_handle(this->pool.handle.get(), handle->curl_handle.get());
            e != CURLM_OK) {
        handle->error = AG_FMT("Failed to add request in pool: {}", curl_multi_strerror(e));
        handle->barrier.set_value();
        return;
    }

    this->worker.running_queue.emplace_back(handle);
}

void dns_over_https::defy_requests() {
    std::list<std::unique_ptr<query_handle>> handle_ptrs;

    this->guard.lock();
    handle_ptrs.swap(this->defied_handles);
    this->guard.unlock();

    for (auto &ptr : handle_ptrs) {
        query_handle *handle = ptr.get();
        tracelog_id(handle, "Defying request");

        handle->cleanup_request();

        std::deque<query_handle *> &queue = this->worker.running_queue;
        queue.erase(std::remove(queue.begin(), queue.end(), handle), queue.end());
    }
}

void dns_over_https::stop_all_with_error(const err_string &e) {
    std::deque<query_handle *> &queue = this->worker.running_queue;
    for (auto i = queue.begin(); i != queue.end();) {
        query_handle *handle = *i;
        handle->error = e;
        handle->cleanup_request();
        i = queue.erase(i);
        handle->barrier.set_value();
    }
}

dns_over_https::exchange_result dns_over_https::exchange(ldns_pkt *request, const dns_message_info *) {
    // register request
    this->guard.lock();
    ++this->worker.requests_counter;
    this->guard.unlock();

    // unregister request at exit for safe destruction
    utils::scope_exit request_unregister(
        [this] () {
            std::scoped_lock lock(this->guard);
            if (0 == --this->worker.requests_counter) {
                this->worker.no_requests_condition.notify_one();
            }
        });

    milliseconds timeout = this->m_options.timeout;

    if (std::unique_lock guard(this->guard); this->resolved == nullptr) {
        bootstrapper::resolve_result resolve_result = this->bootstrapper->get();
        if (resolve_result.error.has_value()) {
            return { nullptr, std::move(resolve_result.error) };
        }
        assert(!resolve_result.addresses.empty());

        milliseconds resolve_time = duration_cast<milliseconds>(resolve_result.time_elapsed);
        if (this->m_options.timeout < resolve_time) {
            return { nullptr, AG_FMT("DNS server name resolving took too much time: {}us",
                resolve_result.time_elapsed.count()) };
        }
        timeout = this->m_options.timeout - resolve_time;

        std::string entry;
        for (const socket_address &address : resolve_result.addresses) {
            assert(address.valid());

            std::string addr = address.str();
            tracelog(log, "Server address: {}", addr);

            auto [ip, port] = utils::split_host_port(addr);
            std::string_view host = get_host_name(this->m_options.address);
            if (entry.empty()) {
                entry = AG_FMT("{}:{}:{}", host, port, ip);
            } else {
                entry = AG_FMT("{},{}", entry, ip);
            }
        }
        this->resolved = curl_slist_ptr(curl_slist_append(nullptr, entry.c_str()));
        tracelog(log, "Resolved server for curl: {}", entry);
    }

    std::unique_ptr<query_handle> handle = create_handle(request, timeout);
    if (handle == nullptr) {
        return { nullptr, "Failed to create request handle" };
    }

    tracelog_id(handle, "Started");

    std::future<void> request_completed = handle->barrier.get_future();
    std::future<void> request_submitted = handle->submit_barrier.get_future();
    this->worker.loop->submit(
            [h = handle.get()] () {
                h->upstream->submit_request(h);
            });

    err_string err;
    ldns_pkt *response = nullptr;
    bool timed_out = false;
    if (std::future_status status = request_completed.wait_for(timeout);
            status != std::future_status::ready) {
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

        std::scoped_lock l(this->guard);
        this->defied_handles.emplace_back(std::move(handle));
        if (this->defied_handles.size() == 1) {
            this->worker.loop->submit([this] () { this->defy_requests(); });
        }
    }

    return { ldns_pkt_ptr(response), std::move(err) };
}
