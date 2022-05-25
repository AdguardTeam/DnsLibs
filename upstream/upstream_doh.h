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
#include "upstream/upstream.h"
#include "common/socket_address.h"
#include "common/event_loop.h"
#include "bootstrapper.h"

#include <ldns/packet.h>
#include <curl/curl.h>
#include <curl/multi.h>
#include <event2/event.h>
#include <event2/event_struct.h>


namespace ag {

using curl_slist_ptr = UniquePtr<curl_slist, &curl_slist_free_all>;
using curl_pool_ptr = UniquePtr<CURLM, &curl_multi_cleanup>;
using event_ptr = UniquePtr<event, &event_free>;

class DohUpstream : public Upstream {
public:
    static constexpr int DEFAULT_PORT = 443;
    static constexpr std::string_view SCHEME = "https://";

    /**
     * @param opts upstream settings
     * @param config factory configuration
     */
    DohUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config);
    ~DohUpstream() override;

    struct QueryHandle;
    struct SocketHandle;
    struct CheckProxyState;

private:
    ErrString init() override;
    ExchangeResult exchange(ldns_pkt *, const DnsMessageInfo *info) override;

    std::unique_ptr<QueryHandle> create_handle(ldns_pkt *request, Millis timeout) const;
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

    static int on_pool_timer_event(CURLM *multi, long timeout_ms, DohUpstream *upstream);
    static int on_socket_update(CURL *handle, curl_socket_t socket, int what,
                                DohUpstream *upstream, SocketHandle *socket_data);
    static void on_event_timeout(evutil_socket_t fd, short kind, void *arg);
    static void on_socket_event(evutil_socket_t fd, short kind, void *arg);
    static curl_socket_t curl_opensocket(void *clientp, curlsocktype purpose, struct curl_sockaddr *address);

    void submit_request(QueryHandle *handle);
    void start_request(QueryHandle *handle, bool ignore_proxy);
    void defy_requests();

    Logger m_log;
    curl_slist_ptr m_resolved = nullptr;
    curl_slist_ptr m_request_headers = nullptr;
    BootstrapperPtr m_bootstrapper;
    std::mutex m_guard;

    struct WorkerDescriptor {
        EventLoopPtr loop = EventLoop::create();
        std::deque<QueryHandle *> running_queue;
        int requests_counter = 0;
        std::condition_variable no_requests_condition;
    };
    WorkerDescriptor m_worker;

    std::list<std::unique_ptr<QueryHandle>> m_defied_handles;

    struct PoolDescriptor {
        curl_pool_ptr handle = nullptr;
        event_ptr timer_event = nullptr;
    };
    PoolDescriptor m_pool;

    std::unique_ptr<CheckProxyState> m_check_proxy;
    std::optional<uint32_t> m_reset_bypassed_proxy_connections_subscribe_id;
};

}
