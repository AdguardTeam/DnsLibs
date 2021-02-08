#pragma once


#include <string>
#include <string_view>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <future>
#include <deque>

#include <ag_logger.h>
#include <ag_defs.h>
#include <upstream.h>
#include <ag_socket_address.h>
#include "bootstrapper.h"

#include <ldns/packet.h>
#include <curl/curl.h>
#include <curl/multi.h>
#include <event2/event.h>
#include <event2/event_struct.h>

#include "event_loop.h"


namespace ag {

using curl_slist_ptr = std::unique_ptr<curl_slist, ftor<&curl_slist_free_all>>;
using curl_pool_ptr = std::unique_ptr<CURLM, ftor<&curl_multi_cleanup>>;
using event_ptr = std::unique_ptr<event, ftor<&event_free>>;

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

private:
    err_string init() override;
    exchange_result exchange(ldns_pkt *) override;

    std::unique_ptr<query_handle> create_handle(ldns_pkt *request, std::chrono::milliseconds timeout) const;
    curl_pool_ptr create_pool() const;
    void add_socket(curl_socket_t socket, int action);
    void read_messages();

    /**
     * Must be called in worker thread
     */
    void stop_all_with_error(err_string e);

    static CURLcode ssl_callback(CURL *curl, void *sslctx, void *arg);
    static int verify_callback(X509_STORE_CTX *ctx, void *arg);

    static int on_pool_timer_event(CURLM *multi, long timeout_ms, dns_over_https *upstream);
    static int on_socket_update(CURL *handle, curl_socket_t socket, int what,
        dns_over_https *upstream, socket_handle *socket_data);
    static void on_event_timeout(evutil_socket_t fd, short kind, void *arg);
    static void on_socket_event(evutil_socket_t fd, short kind, void *arg);
    static int sockopt_callback(void *clientp, curl_socket_t curlfd, curlsocktype purpose);

    static void submit_request(evutil_socket_t, short, void *arg);
    static void defy_requests(evutil_socket_t, short, void *arg);

    static void stop(evutil_socket_t, short, void *arg);

    logger log = create_logger("DOH upstream");
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
};

}
