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
#include "dns/upstream/upstream.h"
#include "common/socket_address.h"
#include "dns/common/event_loop.h"
#include "dns/upstream/bootstrapper.h"

#include <ldns/packet.h>
#include <curl/curl.h>
#include <curl/multi.h>
#include <event2/event.h>
#include <event2/event_struct.h>


namespace ag::dns {

using curl_slist_ptr = UniquePtr<curl_slist, &curl_slist_free_all>;
using curl_pool_ptr = UniquePtr<CURLM, &curl_multi_cleanup>;
using event_ptr = UniquePtr<event, &event_free>;

class DohUpstream : public Upstream {
public:
    static constexpr std::string_view SCHEME_HTTPS = "https://";
    static constexpr std::string_view SCHEME_H3 = "h3://";

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
    Error<InitError> init() override;
    coro::Task<ExchangeResult> exchange(ldns_pkt *, const DnsMessageInfo *info) override;

    std::unique_ptr<QueryHandle> create_handle(ldns_pkt *request, Millis timeout) const;
    curl_pool_ptr create_pool() const;
    void add_socket(curl_socket_t socket, int action);
    void read_messages();

    /**
     * Must be called in worker thread
     */
    void stop_all_with_error(Error<DnsError> e);
    void retry_pending_queries_directly();
    void reset_bypassed_proxy_queries();

    static CURLcode ssl_callback(CURL *curl, void *sslctx, void *arg);
    static int verify_callback(X509_STORE_CTX *ctx, void *arg);

    static int on_pool_timer_event(CURLM *multi, long timeout_ms, DohUpstream *upstream);
    static int on_socket_update(CURL *handle, curl_socket_t socket, int what,
                                DohUpstream *upstream, SocketHandle *socket_data);
    static void on_timeout(uv_timer_t *);
    static void on_poll_event(uv_poll_t *, int status, int events);
    static curl_socket_t curl_opensocket(void *clientp, curlsocktype purpose, struct curl_sockaddr *address);

    auto submit_request(QueryHandle *handle);
    void start_request(QueryHandle *handle, bool ignore_proxy);

    Logger m_log;
    std::shared_ptr<curl_slist> m_resolved = nullptr;
    curl_slist_ptr m_request_headers = nullptr;
    BootstrapperPtr m_bootstrapper;
    std::deque<QueryHandle *> m_running_queue;
    std::shared_ptr<bool> m_shutdown_guard;

    struct PoolDescriptor {
        curl_pool_ptr handle = nullptr;
        UvPtr<uv_timer_t> timer = nullptr;
    };
    PoolDescriptor m_pool;

    std::unique_ptr<CheckProxyState> m_check_proxy;
    std::optional<uint32_t> m_reset_bypassed_proxy_connections_subscribe_id;

    std::string m_curlopt_url;
    int m_curlopt_http_ver = CURL_HTTP_VERSION_2;
};

}  // namespace ag::dns
