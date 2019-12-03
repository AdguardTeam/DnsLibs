#include <cinttypes>
#include <cassert>
#include <algorithm>

#include <ag_utils.h>
#include <ag_defs.h>
#include "upstream_doh.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <ldns/packet.h>
#include <ldns/keys.h>
#include <ldns/rbtree.h>
#include <ldns/host2wire.h>
#include <ldns/wire2host.h>
#include <ldns/host2str.h>


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
static constexpr size_t VERIFY_DEPTH = 4;


struct dns_over_https::query_handle {
    const ag::logger *log = nullptr;
    dns_over_https *upstream = nullptr;
    size_t request_id = 0;
    CURL *curl_handle = nullptr;
    err_string error;
    ldns_buffer_ptr request = nullptr;
    std::vector<uint8_t> response;
    std::promise<void> barrier;

    CURL *create_curl_handle();
    void cleanup_request();
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *arg) {
    dns_over_https::query_handle *h = (dns_over_https::query_handle *)arg;
    size_t full_size = size * nmemb;
    h->response.insert(h->response.end(), (uint8_t *)contents, (uint8_t *)contents + full_size);
    return full_size;
}

static int verify_callback(X509_STORE_CTX *ctx, void *arg) {
    // @todo
    return 1;
}

static CURLcode ssl_callback(CURL *curl, void *sslctx, void *arg) {
    SSL_CTX *ctx = (SSL_CTX *)sslctx;
    SSL_CTX_set_verify_depth(ctx, VERIFY_DEPTH);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_cert_verify_callback(ctx, verify_callback, arg);
    return CURLE_OK;
}

CURL *dns_over_https::query_handle::create_curl_handle() {
    CURL *curl = curl_easy_init();
    if (curl == nullptr) {
        this->error = utils::fmt_string("Failed to init curl handle");
        return nullptr;
    }

    dns_over_https *upstream = this->upstream;
    ldns_buffer *raw_request = this->request.get();
    uint64_t timeout = upstream->timeout.count();
    if (CURLcode e;
            CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_URL, upstream->server_url.data()))
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
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, ssl_callback))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, this))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, true))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, true))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, true))
            || (upstream->resolved != nullptr
                && CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_RESOLVE, upstream->resolved.get())))) {
        this->error = utils::fmt_string("Failed to set options of curl handle: %s (id=%d)",
            curl_easy_strerror(e), e);
        curl_easy_cleanup(curl);
        return nullptr;
    }

    return curl;
}

void dns_over_https::query_handle::cleanup_request() {
    CURLMcode perr = curl_multi_remove_handle(this->upstream->pool.handle.get(), this->curl_handle);
    assert(perr == CURLM_OK);
    curl_easy_cleanup(this->curl_handle);
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
        return nullptr;
    }

    return h;
}

static std::string_view get_host_name(std::string_view url) {
    std::string_view host = url;
    host.remove_prefix(dns_over_https::SCHEME.length());
    host = host.substr(0, host.find('/'));
    return host;
}

static curl_slist_ptr create_resolved_hosts_list(std::string_view url, const upstream::options::address_container &addr) {
    if (std::holds_alternative<std::monostate>(addr)) {
        return nullptr;
    }

    std::string_view host_port = get_host_name(url);
    auto [host, port_str] = utils::split_host_port(host_port);
    int port = dns_over_https::DEFAULT_PORT;
    if (int p; !port_str.empty() && 0 != (p = std::strtol(std::string(port_str).c_str(), nullptr, 10))) {
        port = p;
    }

    std::string entry;
    if (std::holds_alternative<uint8_array<4>>(addr)) {
        const uint8_array<4> &ip = std::get<uint8_array<4>>(addr);
        entry = utils::fmt_string("%.*s:%d:%d.%d.%d.%d",
            (int)host.length(), host.data(), port, ip[0], ip[1], ip[2], ip[3]);
    } else if (std::holds_alternative<uint8_array<16>>(addr)) {
        const uint8_array<16> &ip = std::get<uint8_array<16>>(addr);
        entry = utils::fmt_string("%.*s:%d:[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]",
            (int)host.length(), host.data(), port,
            ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
            ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
    }

    return curl_slist_ptr(curl_slist_append(nullptr, entry.c_str()));
}

static std::shared_ptr<ag::bootstrapper> create_bootstrapper(std::string_view url, const ag::upstream::options &opts) {
    return std::make_shared<ag::bootstrapper>(get_host_name(url), dns_over_https::DEFAULT_PORT, true, opts.bootstrap);
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

dns_over_https::dns_over_https(std::string_view url, const ag::upstream::options &opts)
    : timeout(opts.timeout)
    , server_url(url)
{
    static const initializer ensure_initialized;

    this->resolved = create_resolved_hosts_list(url, opts.server_ip);

    curl_slist *headers;
    if (nullptr == (headers = curl_slist_append(nullptr, "Content-Type: application/dns-message"))
            || nullptr == (headers = curl_slist_append(headers, "Accept: application/dns-message"))) {
        errlog(log, "Failed to create http headers for request");
    }
    this->request_headers.reset(headers);

    this->pool.handle = create_pool();
    assert(this->pool.handle != nullptr);

    if (this->resolved == nullptr) {
        this->bootstrapper = create_bootstrapper(url, opts);
    }
}

void dns_over_https::stop(int, short, void *arg) {
    dns_over_https *upstream = (dns_over_https *)arg;
    upstream->stop_all_with_error("Upstream has been stopped");
}

dns_over_https::~dns_over_https() {
    event_base_once(this->worker.loop->c_base(), 0, EV_TIMEOUT, stop, this, nullptr);
    this->worker.loop->stop();
}

struct dns_over_https::socket_handle {
    curl_socket_t fd = CURLM_BAD_SOCKET;
    int action = 0;
    event event_handle = {};

    ~socket_handle() {
        event_del(&this->event_handle);
    }

    void init(curl_socket_t socket, int act, dns_over_https *upstream) {
        int what = ((act & CURL_POLL_IN) ? EV_READ : 0)
            | ((act & CURL_POLL_OUT) ? EV_WRITE : 0)
            | EV_PERSIST;

        this->fd = socket;
        this->action = act;
        event_del(&this->event_handle);
        event_assign(&this->event_handle, upstream->worker.loop->c_base(), socket, what,
            dns_over_https::on_socket_event, upstream);
        event_add(&this->event_handle, nullptr);
    }
};
using socket_handle = dns_over_https::socket_handle;

int dns_over_https::on_pool_timer_event(CURLM *multi, long timeout_ms, dns_over_https *upstream) {
    tracelog(upstream->log, "{}: Setting timeout to {}ms", __func__, timeout_ms);

    event_ptr &event = upstream->pool.timer_event;
    if (event != nullptr) {
        event_del(event.get());
    }
    if (timeout_ms >= 0) {
        if (event == nullptr) {
            event.reset(event_new(upstream->worker.loop->c_base(), 0, EV_TIMEOUT, on_event_timeout, upstream));
        }
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
        assert(message->easy_handle == handle->curl_handle);

        if (message->data.result != CURLE_OK) {
            handle->error = utils::fmt_string("Failed to perform request: %s", curl_easy_strerror(message->data.result));
        } else {
            tracelog_id(handle, "Got response {}", (void*)message->easy_handle);

            long response_code;
            curl_easy_getinfo(message->easy_handle, CURLINFO_RESPONSE_CODE, &response_code);
            if (response_code < 200 || response_code >= 300) {
                handle->error = utils::fmt_string("Got bad response status: %ld", response_code);
            }
        }

        handle->cleanup_request();

        std::deque<query_handle *> &queue = this->worker.running_queue;
        queue.erase(std::remove(queue.begin(), queue.end(), handle), queue.end());

        handle->barrier.set_value();
    }
}

void dns_over_https::on_socket_event(int fd, short kind, void *arg) {
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

void dns_over_https::on_event_timeout(int fd, short kind, void *arg) {
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

void dns_over_https::submit_request(int, short, void *arg) {
    query_handle *handle = (query_handle *)arg;
    tracelog_id(handle, "Submitting request");

    CURL *curl_handle = handle->create_curl_handle();
    if (curl_handle == nullptr) {
        // error set already in `create_curl_handle`
        handle->barrier.set_value();
        return;
    }

    dns_over_https *upstream = handle->upstream;
    if (CURLMcode e = curl_multi_add_handle(upstream->pool.handle.get(), curl_handle);
            e != CURLM_OK) {
        handle->error = utils::fmt_string("Failed to add request in pool: %s", curl_multi_strerror(e));
        curl_easy_cleanup(curl_handle);
        handle->barrier.set_value();
        return;
    }

    handle->curl_handle = curl_handle;
    upstream->worker.running_queue.emplace_back(handle);
}

void dns_over_https::defy_request(int, short, void *arg) {
    query_handle *handle = (query_handle *)arg;
    tracelog_id(handle, "Defying request");

    dns_over_https *upstream = handle->upstream;
    handle->cleanup_request();

    std::deque<query_handle *> &queue = upstream->worker.running_queue;
    queue.erase(std::remove(queue.begin(), queue.end(), handle), queue.end());

    handle->barrier.set_value();
}

void dns_over_https::stop_all_with_error(err_string e) {
    std::deque<query_handle *> &queue = this->worker.running_queue;
    for (auto i = queue.begin(); i != queue.end();) {
        query_handle *handle = *i;
        handle->error = e;
        handle->cleanup_request();
        i = queue.erase(i);
        handle->barrier.set_value();
    }
}

std::pair<ldns_pkt_ptr, err_string> dns_over_https::exchange(ldns_pkt *request) {
    // @todo: for now it's unsafe to delete an upstream which has in-progress
    // requests - needs to be fixed or handled on the next higher level

    milliseconds timeout = this->timeout;

    if (std::unique_lock guard(this->guard); this->resolved == nullptr) {
        bootstrapper::ret bootstrapper_result = this->bootstrapper->get();
        if (bootstrapper_result.error.has_value()) {
            return { nullptr, std::move(bootstrapper_result.error) };
        }
        assert(bootstrapper_result.address.has_value());
        assert(bootstrapper_result.address->valid());

        std::string addr = bootstrapper_result.address->str();
        tracelog(log, "Server address: {}", addr);
        auto [ip, port] = utils::split_host_port(addr);
        std::string_view host = get_host_name(this->server_url);
        std::string entry = utils::fmt_string("%.*s:%.*s:%.*s",
            (int)host.length(), host.data(), (int)port.length(), port.data(), (int)ip.length(), ip.data());
        this->resolved = curl_slist_ptr(curl_slist_append(this->resolved.release(), entry.c_str()));

        milliseconds resolve_time = duration_cast<milliseconds>(bootstrapper_result.time_elapsed);
        if (this->timeout < resolve_time) {
            return { nullptr, utils::fmt_string("DNS server name resolving took too much time: %" PRId64 "us",
                (int64_t)bootstrapper_result.time_elapsed.count()) };
        }

        timeout = this->timeout - resolve_time;
    }

    std::unique_ptr<query_handle> handle = create_handle(request, timeout);
    if (handle == nullptr) {
        return { nullptr, "Failed to create request handle" };
    }

    tracelog_id(handle, "Started");

    std::future<void> request_completed = handle->barrier.get_future();
    event_base_once(this->worker.loop->c_base(), 0, EV_TIMEOUT, submit_request, handle.get(), nullptr);

    err_string err;
    ldns_pkt *response = nullptr;
    if (std::future_status status = request_completed.wait_for(timeout);
            status != std::future_status::ready) {
        err = utils::fmt_string("Request timed out");
        handle->barrier = std::promise<void>();
        std::future<void> request_defied = handle->barrier.get_future();
        event_base_once(this->worker.loop->c_base(), 0, EV_TIMEOUT, defy_request, handle.get(), nullptr);
        if (std::future_status status = request_defied.wait_for(timeout);
                status != std::future_status::ready) {
            errlog_id(handle, "Failed to defy the request due to timeout");
            assert(0);
        }
    } else if (handle->error.has_value()) {
        err = utils::fmt_string("Failed to perform request: %s", handle->error->c_str());
    } else if (ldns_status status = ldns_wire2pkt(&response, handle->response.data(), handle->response.size());
            status != LDNS_STATUS_OK) {
        err = utils::fmt_string("Failed to parse response: %s", ldns_get_errorstr_by_id(status));
    }

    if (response != nullptr) {
        ldns_pkt_set_id(response, handle->request_id);
    }
    tracelog_id(handle, "Completed");

    return { ldns_pkt_ptr(response), std::move(err) };
}

std::string dns_over_https::address() {
    return this->bootstrapper->address();
}
