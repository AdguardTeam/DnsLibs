#include <future>
#include <cinttypes>
#include <cassert>

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


#define errlog_id(q_, fmt_, ...) errlog(*((q_)->log), "[{}] " fmt_, (q_)->request_id, #__VA_ARGS__)
#define infolog_id(q_, fmt_, ...) infolog(*((q_)->log), "[{}] " fmt_, (q_)->request_id, #__VA_ARGS__)
#define warnlog_id(q_, fmt_, ...) warnlog(*((q_)->log), "[{}] " fmt_, (q_)->request_id, #__VA_ARGS__)
#define dbglog_id(q_, fmt_, ...) dbglog(*((q_)->log), "[{}] " fmt_, (q_)->request_id, #__VA_ARGS__)
#define tracelog_id(q_, fmt_, ...) tracelog(*((q_)->log), "[{}] " fmt_, (q_)->request_id, #__VA_ARGS__)


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


using curl_handle_ptr = std::unique_ptr<CURL, ag::ftor<&curl_easy_cleanup>>;


static constexpr std::string_view USER_AGENT = "ag-dns";
static constexpr size_t VERIFY_DEPTH = 4;


struct dns_over_https::query_handle {
    size_t request_id;
    const ag::logger *log;
    curl_handle_ptr curl_handle = nullptr;
    CURLMcode pool_result = CURLM_OK;
    CURLcode request_result = CURLE_OK;
    curl_slist_ptr headers = nullptr;
    ldns_buffer_ptr request = nullptr;
    std::vector<uint8_t> response;
    std::promise<void> barrier;
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

std::unique_ptr<dns_over_https::query_handle> dns_over_https::create_handle(ldns_pkt *request,  milliseconds timeout) const {
    std::unique_ptr<query_handle> h = std::make_unique<query_handle>();
    h->log = &this->log;
    h->request_id = ldns_pkt_id(request);
    ldns_pkt_set_id(request, 0);

    h->curl_handle.reset(curl_easy_init());
    if (h->curl_handle == nullptr) {
        errlog_id(h, "Failed to init curl handle");
        return nullptr;
    }

    h->request.reset(ldns_buffer_new(512));
    ldns_status status = ldns_pkt2buffer_wire(h->request.get(), request);
    if (status != LDNS_STATUS_OK) {
        errlog_id(h, "Failed to serialize packet: {}", ldns_get_errorstr_by_id(status));
        return nullptr;
    }

    curl_slist *headers;
    if (nullptr == (headers = curl_slist_append(nullptr, "Content-Type: application/dns-message"))
            || nullptr == (headers = curl_slist_append(headers, "Accept: application/dns-message"))) {
        errlog_id(h, "Failed to create http headers for DOH request");
        return nullptr;
    }
    h->headers.reset(headers);

    CURL *curl = h->curl_handle.get();
    ldns_buffer *raw_request = h->request.get();
    if (CURLcode e;
            CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_URL, this->server_url.data()))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, true))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout.count()))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeout.count()))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_WRITEDATA, h.get()))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT.data()))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ldns_buffer_at(raw_request, 0)))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, ldns_buffer_position(raw_request)))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_PRIVATE, h.get()))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, ssl_callback))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, h.get()))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, true))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, true))
            || CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, true))
            || (this->resolved != nullptr
                && CURLE_OK != (e = curl_easy_setopt(curl, CURLOPT_RESOLVE, this->resolved.get())))) {
        errlog_id(h, "Failed to set options of curl handle: {}", curl_easy_strerror(e));
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

static curl_slist_ptr create_resolved_hosts_list(std::string_view url, const ag::ip_address_variant &addr) {
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

dns_over_https::dns_over_https(std::string_view url, const ag::upstream::options &opts)
    : timeout(opts.timeout)
    , server_url(url)
{
    static const initializer ensure_initialized;

    this->resolved = create_resolved_hosts_list(url, opts.server_ip);
    this->handle_pool = curl_pool_ptr(curl_multi_init());
    if (this->resolved == nullptr) {
        this->bootstrapper = create_bootstrapper(url, opts);
    }
    this->worker.thread =
        std::thread([this] () {
            while (!this->stop) {
                run(this);
            }
        });
}

dns_over_https::~dns_over_https() {
    this->worker.guard.lock();
    this->stop = true;
    this->worker.run_condition.notify_one();
    this->worker.guard.unlock();
    this->worker.thread.join();
}

void dns_over_https::run(dns_over_https *us) {
    CURLM *pool = us->handle_pool.get();

    {
        std::unique_lock guard(us->worker.guard);
        while (us->pending_queue.empty() && us->running_queue.empty() && !us->stop) {
            us->worker.run_condition.wait(guard);
        }
        // @todo: for now it's unsafe to delete an upstream which has in-progress
        // requests - needs to be fixed or handled on the next higher level

        for (auto i = us->pending_queue.begin(); i != us->pending_queue.end();) {
            query_handle *handle = *i;
            curl_multi_add_handle(pool, handle->curl_handle.get());
            dbglog_id(handle, "Request started");
            i = us->pending_queue.erase(i);
            us->running_queue.emplace_back(handle);
        }
    }

    int still_running = 0;
    if (CURLMcode err = curl_multi_perform(pool, &still_running); err != CURLM_OK) {
        std::unique_lock lock(us->worker.guard);
        for (auto i = us->running_queue.begin(); i != us->running_queue.end();) {
            query_handle *handle = *i;
            handle->pool_result = err;
            handle->barrier.set_value();
            i = us->running_queue.erase(i);
        }
        return;
    }

    int queued;
    CURLMsg *message;
    while (nullptr != (message = curl_multi_info_read(pool, &queued))) {
        if (message->msg != CURLMSG_DONE) {
            continue;
        }

        query_handle *query_handle;
        curl_easy_getinfo(message->easy_handle, CURLINFO_PRIVATE, &query_handle);
        assert(message->easy_handle == query_handle->curl_handle.get());

        query_handle->request_result = message->data.result;
        curl_multi_remove_handle(pool, message->easy_handle);
        dbglog_id(query_handle, "Got response");
        query_handle->barrier.set_value();
        us->worker.guard.lock();
        us->running_queue.remove(query_handle);
        us->worker.guard.unlock();
    }
}

std::pair<ldns_pkt_ptr, err_string> dns_over_https::exchange(ldns_pkt *request) {
    milliseconds timeout = this->timeout;

    if (std::unique_lock guard(this->worker.guard); this->resolved == nullptr) {
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

    std::future<void> condition = handle->barrier.get_future();

    this->worker.guard.lock();
    this->pending_queue.emplace_back(handle.get());
    this->worker.guard.unlock();

    this->worker.guard.lock();
    this->worker.run_condition.notify_one();
    this->worker.guard.unlock();

    tracelog_id(handle, "Started");

    err_string err;
    ldns_pkt *response = nullptr;
    if (std::future_status status = condition.wait_for(timeout);
            status != std::future_status::ready) {
        err = utils::fmt_string("Request timed out");
        this->worker.guard.lock();
        this->running_queue.remove(handle.get());
        this->worker.guard.unlock();
    } else if (handle->pool_result != CURLM_OK) {
        err = utils::fmt_string("Failed to perform request: %s", curl_multi_strerror(handle->pool_result));
    } else if (handle->request_result != CURLE_OK) {
        err = utils::fmt_string("Failed to perform DOH request: %s", curl_easy_strerror(handle->request_result));
    } else {
        long response_code;
        curl_easy_getinfo(handle->curl_handle.get(), CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code >= 200 && response_code < 300) {
            if (ldns_status status = ldns_wire2pkt(&response, handle->response.data(), handle->response.size());
                    status != LDNS_STATUS_OK) {
                err = utils::fmt_string("Failed to parse DOH response: %s", ldns_get_errorstr_by_id(status));
            } else {
                ldns_pkt_set_id(response, handle->request_id);
            }
        } else {
            err = utils::fmt_string("Got bad DOH response status: %ld", response_code);
        }
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
