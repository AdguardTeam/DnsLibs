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
     * @param fingerprints list of SPKI fingerprints to verify
     */
    DohUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config,
            std::vector<CertFingerprint> fingerprints);
    ~DohUpstream() override;

    struct QueryHandle;
    struct SocketHandle;
    struct CheckProxyState;

private:
    using CURL_ptr = UniquePtr<CURL, &curl_easy_cleanup>;

    struct ConnectionPool {
        DohUpstream *parent = nullptr;
        curl_pool_ptr handle = nullptr;
        UvPtr<uv_timer_t> timer = nullptr;

        ConnectionPool() = default;
        ~ConnectionPool() = default;

        bool init(DohUpstream *parent);

        ConnectionPool(const ConnectionPool &) = delete;
        ConnectionPool &operator=(const ConnectionPool &) = delete;

        ConnectionPool(ConnectionPool &&) = delete;
        ConnectionPool &operator=(ConnectionPool &&) = delete;
    };

    Error<InitError> init() override;
    coro::Task<ExchangeResult> exchange(const ldns_pkt *, const DnsMessageInfo *info) override;

    std::unique_ptr<QueryHandle> create_handle(const ldns_pkt *request, Millis timeout) const;
    void read_messages();

    /**
     * Must be called in worker thread
     */
    void stop_all_with_error(Error<DnsError> e);
    void retry_pending_queries(bool ignoreProxy);
    void reset_bypassed_proxy_queries();

    static CURLcode ssl_callback(CURL *curl, void *sslctx, void *arg);
    static int verify_callback(X509_STORE_CTX *ctx, void *arg);

    static int on_pool_timer_event(CURLM *multi, long timeout_ms, DohUpstream::ConnectionPool *pool);
    static int on_socket_update(CURL *handle, curl_socket_t socket, int what,
                                DohUpstream::ConnectionPool *pool, SocketHandle *socket_data);
    static void on_timeout(uv_timer_t *);
    static void on_poll_event(uv_poll_t *, int status, int events);
    static curl_socket_t curl_opensocket(void *clientp, curlsocktype purpose, struct curl_sockaddr *address);
    static int curl_prereq(
            void *clientp, char *conn_primary_ip, char *conn_local_ip, int conn_primary_port, int conn_local_port);

    auto submit_request(QueryHandle *handle);
    void start_request(QueryHandle *handle, bool ignore_proxy);

    void start_httpver_probe();
    void cleanup_httpver_probe();

    Logger m_log;
    std::shared_ptr<curl_slist> m_resolved = nullptr;
    curl_slist_ptr m_request_headers = nullptr;
    BootstrapperPtr m_bootstrapper;
    std::deque<QueryHandle *> m_running_queue;
    std::shared_ptr<bool> m_shutdown_guard;

    ConnectionPool m_pool;

    std::unique_ptr<ConnectionPool> m_h2_probe_pool;
    std::unique_ptr<ConnectionPool> m_h3_probe_pool;
    std::unique_ptr<QueryHandle> m_h2_probe_handle;
    std::unique_ptr<QueryHandle> m_h3_probe_handle;
    EventLoop::TaskId m_httpver_probe_cleanup_task;

    std::unique_ptr<CheckProxyState> m_check_proxy;
    std::optional<uint32_t> m_reset_bypassed_proxy_connections_subscribe_id;
    std::vector<CertFingerprint> m_fingerprints;

    std::string m_curlopt_url;
    int m_curlopt_http_ver = CURL_HTTP_VERSION_NONE;

    // See FIXME-66691.
    std::vector<CURL_ptr> m_curl_easy_graveyard;
};

}  // namespace ag::dns
