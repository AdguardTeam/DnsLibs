#pragma once


#include <string>
#include <string_view>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <future>
#include <deque>
#include <list>

#include "common/logger.h"
#include "common/defs.h"
#include <upstream.h>
#include "common/socket_address.h"
#include <ag_event_loop.h>
#include "bootstrapper.h"

#include <ldns/packet.h>
#include <curl/curl.h>
#include <curl/multi.h>
#include <event2/event.h>
#include <event2/event_struct.h>


namespace ag {

using curl_slist_ptr = std::unique_ptr<curl_slist, Ftor<&curl_slist_free_all>>;
using curl_pool_ptr = std::unique_ptr<CURLM, Ftor<&curl_multi_cleanup>>;
using event_ptr = std::unique_ptr<event, Ftor<&event_free>>;

class dns_over_https : public upstream {
public:
    static constexpr int DEFAULT_PORT = 443;
    static constexpr std::string_view SCHEME = "https://";

    /**
     * @param opts upstream settings
     * @param config factory configuration
     */
    dns_over_https(const upstream_options &opts, const upstream_factory_config &config);
    ~dns_over_https() override;

    struct query_handle;
    struct socket_handle;
    struct check_proxy_state;

private:
    ErrString init() override;
    exchange_result exchange(ldns_pkt *, const dns_message_info *info) override;

    std::unique_ptr<query_handle> create_handle(ldns_pkt *request, std::chrono::milliseconds timeout) const;
    curl_pool_ptr create_pool() const;
    void add_socket(curl_socket_t socket, int action);
    void read_messages();

    /**
     * Must be called in worker thread
     */
    void stop_all_with_error(const ErrString &e);
    void retry_pending_queries_directly();
    void reset_bypassed_proxy_queries();

    static CURLcode ssl_callback(CURL *curl, void *sslctx, void *arg);
    static int verify_callback(X509_STORE_CTX *ctx, void *arg);

    static int on_pool_timer_event(CURLM *multi, long timeout_ms, dns_over_https *upstream);
    static int on_socket_update(CURL *handle, curl_socket_t socket, int what,
        dns_over_https *upstream, socket_handle *socket_data);
    static void on_event_timeout(evutil_socket_t fd, short kind, void *arg);
    static void on_socket_event(evutil_socket_t fd, short kind, void *arg);
    static curl_socket_t curl_opensocket(void *clientp, curlsocktype purpose, struct curl_sockaddr *address);

    void submit_request(query_handle *handle);
    void start_request(query_handle *handle, bool ignore_proxy);
    void defy_requests();

    Logger log;
    curl_slist_ptr resolved = nullptr;
    curl_slist_ptr request_headers = nullptr;
    bootstrapper_ptr bootstrapper;
    std::mutex guard;

    struct worker_descriptor {
        event_loop_ptr loop = event_loop::create();
        std::deque<query_handle *> running_queue;
        int requests_counter = 0;
        std::condition_variable no_requests_condition;
    };
    worker_descriptor worker;

    std::list<std::unique_ptr<query_handle>> defied_handles;

    struct pool_descriptor {
        curl_pool_ptr handle = nullptr;
        event_ptr timer_event = nullptr;
    };
    pool_descriptor pool;

    std::unique_ptr<check_proxy_state> check_proxy;
    std::optional<uint32_t> reset_bypassed_proxy_connections_subscribe_id;
};

}
