#pragma once

#include <list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

#include <ldns/ldns.h>
#include <nghttp2/nghttp2.h>

#include "common/coro.h"
#include "common/defs.h"
#include "common/http/headers.h"
#include "common/socket_address.h"
#include "dns/common/event_loop.h"
#include "dns/net/aio_socket.h"
#include "dns/net/socket.h"
#include "dns/upstream/bootstrapper.h"
#include "dns/upstream/upstream.h"

namespace ag::dns {

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

    DohUpstream() = delete;
    DohUpstream(const DohUpstream &) = delete;
    DohUpstream &operator=(const DohUpstream &) = delete;
    DohUpstream(DohUpstream &&) = delete;
    DohUpstream &operator=(DohUpstream &&) = delete;

private:
    enum class ConnectionState : int;
    struct HttpAwaitable;
    struct ConnectAwaitable;

    struct HttpConnection;
    struct Http2Connection;
    friend struct Http2Connection;
    struct Http3Connection;
    friend struct Http3Connection;

    Error<InitError> init() override;
    coro::Task<ExchangeResult> exchange(const ldns_pkt *, const DnsMessageInfo *info) override;

    coro::Task<void> drive_connection(Millis timeout);
    coro::Task<Result<HttpConnection *, DnsError>> establish_connection(HttpConnection *http_conn);
    coro::Task<Result<HttpConnection *, DnsError>> establish_any_of_connections(
            HttpConnection *left, HttpConnection *right);
    coro::Task<ExchangeResult> exchange(Millis timeout, const ldns_pkt *request);
    coro::Task<ExchangeResult> wait_for_reply(uint64_t stream_id, uint16_t query_id);
    Result<uint64_t, DnsError> send_request(const ldns_pkt *request);
    void close_connection(const Error<DnsError> &error);
    void cancel_all(const Error<DnsError> &error);
    void cancel_read_timer();
    void refresh_read_timer();

    uint32_t m_id;
    ConnectionState m_connection_state{};
    std::unique_ptr<HttpConnection> m_http_conn;
    std::unordered_map<uint64_t, std::unique_ptr<HttpAwaitable>> m_streams;
    size_t m_next_query_id = 0;
    std::unordered_map<size_t, std::unique_ptr<ConnectAwaitable>> m_connect_waiters;
    size_t m_pending_queries_counter = 0;
    std::optional<EventLoop::TaskId> m_read_timer_task;
    std::optional<Bootstrapper> m_bootstrapper;
    http::Request m_request_template;
    std::string m_path;
    std::optional<http::Version> m_http_version;
    TlsSessionCache m_tls_session_cache;
    std::vector<CertFingerprint> m_fingerprints;
    std::shared_ptr<bool> m_shutdown_guard = std::make_shared<bool>(true);
};

} // namespace ag::dns
