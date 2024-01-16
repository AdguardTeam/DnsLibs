#include <array>
#include <atomic>
#include <cassert>
#include <chrono>

#include <ada.h>
#include <ada/url.h>
#include <magic_enum/magic_enum.hpp>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include "common/base64.h"
#include "common/http/http2.h"
#include "common/http/http3.h"
#include "common/logger.h"
#include "common/parallel.h"
#include "common/utils.h"
#include "upstream_doh.h"

enum class ag::dns::DohUpstream::ConnectionState : int {
    IDLE,
    CONNECTING,
    CONNECTED,
};

struct ag::dns::DohUpstream::ConnectWaiter {
    std::coroutine_handle<> handle;
    Error<DnsError> error;
    bool complete = false;

    ~ConnectWaiter() {
        if (!complete && handle != nullptr) {
            if (error == nullptr) {
                error = make_error(DnsError::AE_SHUTTING_DOWN);
            }
            std::exchange(handle, nullptr).resume();
        }
    }

    void notify_result(Error<DnsError> e) {
        error = std::move(e);
        assert(!complete);
        complete = true;
        std::exchange(handle, nullptr).resume();
    }
};

struct ag::dns::DohUpstream::ConnectAwaitable {
    ConnectWaiter &waiter;

    explicit ConnectAwaitable(ConnectWaiter &waiter)
            : waiter(waiter) {
    }

    [[nodiscard]] bool await_ready() const {
        return waiter.complete;
    }
    void await_suspend(std::coroutine_handle<> h) {
        waiter.handle = std::move(h);
    }
    Error<DnsError> await_resume() {
        return waiter.error;
    }
};

struct ag::dns::DohUpstream::ReplyWaiter {
    enum State {
        WAITING_RESPONSE_HEADERS,
        WAITING_RESPONSE_BODY,
        DONE,
    };

    State state{};
    std::coroutine_handle<> handle;
    uint16_t query_id;
    std::optional<http::Response> response;
    std::vector<uint8_t> reply_buffer;
    ldns_pkt_ptr reply;
    Error<DnsError> error;

    // monostate is needed to make it default-constructible (`ag::Result`'s restriction)
    using Result = Result<std::variant<std::monostate, http::Response, ldns_pkt_ptr>, DnsError>;

    explicit ReplyWaiter(uint16_t query_id);
    ~ReplyWaiter();
    ReplyWaiter() = delete;
    ReplyWaiter(const ReplyWaiter &) = delete;
    ReplyWaiter &operator=(const ReplyWaiter &) = delete;
    ReplyWaiter(ReplyWaiter &&) = delete;
    ReplyWaiter &operator=(ReplyWaiter &&) = delete;

    void notify_response(http::Response r);
    void notify_reply(ldns_pkt_ptr r);
    void notify_error(Error<DnsError> e);
};

struct ag::dns::DohUpstream::ReplyAwaitable {
    ReplyWaiter &waiter;

    explicit ReplyAwaitable(ReplyWaiter &waiter)
            : waiter(waiter) {
    }

    [[nodiscard]] bool await_ready() const {
        return waiter.response.has_value() || waiter.reply != nullptr || waiter.error != nullptr;
    }
    void await_suspend(std::coroutine_handle<> h) {
        waiter.handle = h;
    }
    ReplyWaiter::Result await_resume() {
        if (waiter.error != nullptr) {
            return std::exchange(waiter.error, nullptr);
        }
        if (waiter.response.has_value()) {
            return std::exchange(waiter.response, std::nullopt).value(); // NOLINT(*-unchecked-optional-access)
        }
        if (waiter.reply != nullptr) {
            return std::exchange(waiter.reply, nullptr);
        }
        return waiter.error;
    }
};

struct ag::dns::DohUpstream::HttpConnection { // NOLINT(*-special-member-functions)
    explicit HttpConnection(DohUpstream *parent)
            : parent_shutdown_guard(parent->m_shutdown_guard)
            , parent(parent)
            , loop(parent->m_config.loop)
    {
    }

    HttpConnection() = delete;
    HttpConnection(const HttpConnection &) = delete;
    HttpConnection &operator=(const HttpConnection &) = delete;
    HttpConnection(HttpConnection &&) = delete;
    HttpConnection &operator=(HttpConnection &&) = delete;

    virtual ~HttpConnection() {
        shutdown_guard.reset();
    }
    [[nodiscard]] virtual http::Version version() const = 0;
    [[nodiscard]] virtual coro::Task<Error<DnsError>> establish(std::string hostname, SocketAddress peer) = 0;
    [[nodiscard]] virtual Result<uint64_t, DnsError> submit_request(const http::Request &request) = 0;
    virtual Error<DnsError> reset_stream(uint64_t stream_id) = 0;
    [[nodiscard]] virtual Error<DnsError> flush() = 0;
    [[nodiscard]] virtual coro::Task<Error<DnsError>> drive_io() = 0;

    static void on_response(void *arg, uint64_t stream_id, http::Response response);
    static void on_body(void *arg, uint64_t stream_id, Uint8View chunk);
    static void on_stream_read_finished(void *arg, uint64_t stream_id);
    static void on_stream_closed(void *arg, uint64_t stream_id, Error<DnsError> error);
    static void on_close(void *arg, Error<DnsError> error);
    static void on_output(void *arg, Uint8View chunk);

    std::shared_ptr<bool> shutdown_guard = std::make_shared<bool>();
    std::weak_ptr<bool> parent_shutdown_guard;
    DohUpstream *parent;
    EventLoop &loop;
    std::optional<AioSocket> io;
    static inline uint32_t next_id = 0; // NOLINT(*-identifier-naming)
    uint32_t id = next_id++;
};

struct ag::dns::DohUpstream::Http2Connection : public ag::dns::DohUpstream::HttpConnection {
    explicit Http2Connection(DohUpstream *parent)
            : HttpConnection(parent) {
    }
    ~Http2Connection() override {
        shutdown_guard.reset();
    }
    Http2Connection(const Http2Connection &) = delete;
    Http2Connection &operator=(const Http2Connection &) = delete;
    Http2Connection(Http2Connection &&) = delete;
    Http2Connection &operator=(Http2Connection &&) = delete;

    [[nodiscard]] http::Version version() const override;
    [[nodiscard]] coro::Task<Error<DnsError>> establish(std::string hostname, SocketAddress peer) override;
    [[nodiscard]] Result<uint64_t, DnsError> submit_request(const http::Request &request) override;
    Error<DnsError> reset_stream(uint64_t stream_id) override;
    [[nodiscard]] Error<DnsError> flush() override;
    [[nodiscard]] coro::Task<Error<DnsError>> drive_io() override;

    [[nodiscard]] coro::Task<Error<DnsError>> connect_socket(std::string hostname, SocketAddress peer);
    static bool on_socket_read(void *arg, Uint8View data);

    std::unique_ptr<http::Http2Client> session;
    Error<DnsError> session_error;
};

struct ag::dns::DohUpstream::Http3Connection : public ag::dns::DohUpstream::HttpConnection {
    enum class State {
        IDLE,
        HANDSHAKING,
        CONNECTED,
    };

    explicit Http3Connection(DohUpstream *parent)
            : HttpConnection(parent) {
    }
    ~Http3Connection() override {
        shutdown_guard.reset();

        if (auto task = std::exchange(expiry_task, std::nullopt); task.has_value()) {
            loop.cancel(task.value());
        }
    }

    Http3Connection(const Http3Connection &) = delete;
    Http3Connection &operator=(const Http3Connection &) = delete;
    Http3Connection(Http3Connection &&) = delete;
    Http3Connection &operator=(Http3Connection &&) = delete;

    [[nodiscard]] http::Version version() const override;
    [[nodiscard]] coro::Task<Error<DnsError>> establish(std::string hostname, SocketAddress peer) override;
    [[nodiscard]] Result<uint64_t, DnsError> submit_request(const http::Request &request) override;
    Error<DnsError> reset_stream(uint64_t stream_id) override;
    [[nodiscard]] Error<DnsError> flush() override;
    [[nodiscard]] coro::Task<Error<DnsError>> drive_io() override;
    [[nodiscard]] coro::Task<Error<DnsError>> connect_socket(std::string hostname, SocketAddress peer);
    [[nodiscard]] Error<DnsError> handle_expiry();

    static void on_handshake_completed(void *arg);
    static void on_expiry_update(void *arg, ag::Nanos period);
    static int on_certificate_verify(X509_STORE_CTX *ctx, void *arg);
    static bool on_socket_read(void *arg, Uint8View data);

    std::unique_ptr<http::Http3Client> session;
    SocketAddress local{"0.0.0.0:0"};
    SocketAddress remote;
    std::optional<EventLoop::TaskId> expiry_task;
    State state = State::IDLE;
    Error<DnsError> session_error;
};

using std::chrono::duration_cast;

#define log_upstream(lvl_, self_, fmt_, ...) lvl_##log(g_logger, "[{}] " fmt_, (self_)->m_id, ##__VA_ARGS__)
#define log_hconn(lvl_, self_, fmt_, ...)                                                                              \
    lvl_##log(g_logger, "[{}] [{}-{}] " fmt_, (self_)->parent->m_id, (self_)->id,                                      \
            ((self_)->version() == http::HTTP_2_0) ? "h2" : "h3", ##__VA_ARGS__)
#define log_query(lvl_, hconn_, qid_, fmt_, ...)                                                                       \
    lvl_##log(g_logger, "[{}] [{}-{}] [{}] " fmt_, (hconn_)->parent->m_id, (hconn_)->id,                               \
            ((hconn_)->version() == http::HTTP_2_0) ? "h2" : "h3", qid_, ##__VA_ARGS__)

static const ag::Logger g_logger("DOH upstream");
static std::atomic<uint32_t> g_next_id = 0; // NOLINT(*-avoid-non-const-global-variables)

// NOLINTNEXTLINE(*-avoid-reference-coroutine-parameters)
static ag::coro::Task<ag::Error<ag::dns::DnsError>> wait_timeout(ag::dns::EventLoop &loop, ag::Millis timeout) {
    co_await loop.co_sleep(timeout);
    co_return make_error(ag::dns::DnsError::AE_TIMED_OUT);
};

ag::dns::DohUpstream::DohUpstream(
        const UpstreamOptions &opts, const UpstreamFactoryConfig &config, std::vector<CertFingerprint> fingerprints)
        : Upstream(opts, config)
        , m_id(g_next_id.fetch_add(1, std::memory_order_relaxed))
        , m_request_template(http::HTTP_2_0, "GET")
        , m_tls_session_cache(opts.address)
        , m_fingerprints(std::move(fingerprints)) {
    m_request_template.scheme("https");
    m_request_template.headers().put("accept", "application/dns-message");
}

ag::dns::DohUpstream::~DohUpstream() {
    m_shutdown_guard.reset();
    close_connection(make_error(DnsError::AE_SHUTTING_DOWN));
}

ag::Error<ag::dns::Upstream::InitError> ag::dns::DohUpstream::init() {
    auto error = this->init_url_port(/*allow_creds*/ true, /*allow_path*/ true, DEFAULT_DOH_PORT);
    if (error) {
        return error;
    }

    if (m_options.bootstrap.empty() && std::holds_alternative<std::monostate>(m_options.resolved_server_ip)
            && !SocketAddress(m_url.get_hostname(), m_port).valid()) {
        return make_error(InitError::AE_EMPTY_BOOTSTRAP);
    }

    std::string address;
    if (auto resolved = ag::SocketAddress(m_options.resolved_server_ip, DEFAULT_DOH_PORT); resolved.valid()) {
        address = resolved.host_str(/*ipv6_brackets*/ true);
    } else {
        address = m_url.get_hostname();
    }

    Bootstrapper &bootstrapper = m_bootstrapper.emplace(Bootstrapper::Params{
            .address_string = address,
            .default_port = m_port,
            .bootstrap = m_options.bootstrap,
            .timeout = m_config.timeout,
            .upstream_config = m_config,
            .outbound_interface = m_options.outbound_interface,
    });

    if (Error<Bootstrapper::BootstrapperError> err = bootstrapper.init()) {
        return make_error(InitError::AE_EMPTY_BOOTSTRAP, std::move(err));
    }

    m_request_template.authority(std::string(m_url.get_hostname()));
    if (!m_url.get_username().empty() && !m_url.get_password().empty()) {
        auto creds_fmt = AG_FMT("{}:{}", m_url.get_username(), m_url.get_password());
        auto creds_base64 = ag::encode_to_base64(as_u8v(creds_fmt), false);
        m_request_template.headers().put("Authorization", AG_FMT("Basic {}", creds_base64));
    }
    m_path = m_url.get_pathname();
    log_upstream(dbg, this, "Prepared request template: {}", m_request_template);

    if (m_options.address.starts_with(DohUpstream::SCHEME_H3)) {
        m_http_version = http::HTTP_3_0;
    } else if (!m_config.enable_http3) {
        m_http_version = http::HTTP_2_0;
    }

    return {};
}

ag::coro::Task<ag::dns::Upstream::ExchangeResult> ag::dns::DohUpstream::exchange(
        const ldns_pkt *request, const DnsMessageInfo *info) {
    std::weak_ptr<bool> shutdown_guard = m_shutdown_guard;
    Millis timeout = m_config.timeout;
    SteadyClock::time_point start_ts = SteadyClock::now();
    size_t query_id = m_next_query_id++;

    if (m_pending_queries_counter++ == 0) {
        refresh_read_timer();
    }

    ExchangeResult result;
    while (true) {
        switch (m_connection_state) {
        case ConnectionState::IDLE: {
            m_connection_state = ConnectionState::CONNECTING;

            coro::run_detached([](std::weak_ptr<bool> shutdown_guard, DohUpstream *self,
                                       SteadyClock::time_point start_ts) -> coro::Task<void> {
                if (!shutdown_guard.expired()) {
                    co_await self->drive_connection(
                            self->m_config.timeout - duration_cast<Millis>(SteadyClock::now() - start_ts));
                }
                co_return;
            }(shutdown_guard, this, start_ts));
            break;
        }
        case ConnectionState::CONNECTING: {
            ConnectWaiter &waiter =
                    *m_connect_waiters.emplace(query_id, std::make_unique<ConnectWaiter>()).first->second;
            timeout = timeout - duration_cast<Millis>(SteadyClock::now() - start_ts);
            auto error = co_await parallel::any_of<Error<DnsError>>(
                    ConnectAwaitable(waiter), wait_timeout(m_config.loop, timeout));
            if (shutdown_guard.expired()) {
                result = make_error(DnsError::AE_SHUTTING_DOWN);
                goto loop_exit;
            }
            m_connect_waiters.erase(query_id);
            if (error != nullptr) {
                result = std::move(error);
                goto loop_exit;
            }
            break;
        }
        case ConnectionState::CONNECTED: {
            timeout = timeout - duration_cast<Millis>(SteadyClock::now() - start_ts);
            result = co_await exchange(timeout, request);
            goto loop_exit;
        }
        }
    }

loop_exit:
    if (shutdown_guard.expired()) {
        co_return result;
    }

    if (--m_pending_queries_counter == 0 && (result.has_value() || result.error()->value() != DnsError::AE_TIMED_OUT)) {
        cancel_read_timer();
    }

    co_await m_config.loop.co_submit();
    if (shutdown_guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }

    co_return result;
}

ag::coro::Task<void> ag::dns::DohUpstream::drive_connection(Millis handshake_timeout) {
    SteadyClock::time_point start_ts = SteadyClock::now();

    if (m_connection_state != ConnectionState::CONNECTING) {
        ConnectionState state = std::exchange(m_connection_state, ConnectionState::IDLE);
        close_connection(
                make_error(DnsError::AE_INTERNAL_ERROR, AG_FMT("Unexpected state: {}", magic_enum::enum_name(state))));
        co_return;
    }

    if (m_http_conn != nullptr) {
        close_connection(make_error(DnsError::AE_INTERNAL_ERROR, "Unreachable"));
        co_return;
    }

    std::weak_ptr<bool> shutdown_guard = m_shutdown_guard;
    log_upstream(trace, this, "Bootstrapping...");
    Bootstrapper::ResolveResult resolved = co_await m_bootstrapper->get(); // NOLINT(*-unchecked-optional-access)
    if (shutdown_guard.expired()) {
        co_return;
    }
    if (resolved.error) {
        close_connection(make_error(DnsError::AE_BOOTSTRAP_ERROR, resolved.error));
        co_return;
    }
    if (resolved.addresses.empty()) {
        close_connection(make_error(DnsError::AE_BOOTSTRAP_ERROR, "Empty address list"));
        co_return;
    }
    log_upstream(trace, this, "Bootstrapped");

    m_pending_connections = std::make_shared<std::vector<std::unique_ptr<HttpConnection>>>();
    auto connections_guard = std::weak_ptr<std::vector<std::unique_ptr<HttpConnection>>>(m_pending_connections);
    coro::Task<Result<HttpConnection *, DnsError>> connector;
    SocketAddress peer = resolved.addresses.at(0);
    if (m_http_version == http::HTTP_3_0) {
        m_pending_connections->push_back(std::make_unique<Http3Connection>(this));
        connector = establish_connection(m_pending_connections->back().get(), peer);
    } else if (m_http_version == http::HTTP_2_0) {
        m_pending_connections->emplace_back(std::make_unique<Http2Connection>(this));
        connector = establish_connection(m_pending_connections->back().get(), peer);
    } else {
        m_pending_connections->emplace_back(std::make_unique<Http3Connection>(this));
        m_pending_connections->emplace_back(std::make_unique<Http2Connection>(this));
        connector = establish_any_of_connections(*m_pending_connections, peer);
    }

    auto http_conn = co_await parallel::any_of<Result<HttpConnection *, DnsError>>(
            connector, wait_timeout(m_config.loop, handshake_timeout));
    if (shutdown_guard.expired()) {
        co_return;
    }

    co_await m_config.loop.co_submit();
    if (shutdown_guard.expired()) {
        co_return;
    }
    if (connections_guard.expired()) {
        co_return;
    }

    if (std::exchange(m_retry_connection, false) && 1 < resolved.addresses.size()) {
        log_upstream(dbg, this, "Retrying connection");
        m_http_conn.reset();
        m_pending_connections.reset();
        cancel_read_timer();
        assert(m_connection_state == ConnectionState::CONNECTING);
        co_return co_await drive_connection(handshake_timeout - duration_cast<Millis>(SteadyClock::now() - start_ts));
    }

    if (http_conn.has_error()) {
        if (http_conn.error()->value() == DnsError::AE_TIMED_OUT) {
            m_bootstrapper->remove_resolved(peer); // NOLINT(*-unchecked-optional-access)
        }
        m_pending_connections.reset();
        close_connection(http_conn.error());
        co_return;
    }

    m_connection_state = ConnectionState::CONNECTED;
    m_http_conn = std::move(*std::find_if(m_pending_connections->begin(), m_pending_connections->end(),
            [&](auto &conn){ return conn.get() == http_conn.value(); }));
    m_request_template.version(m_http_conn->version());
    m_pending_connections.reset();

    for (auto &[_, waiter] : std::exchange(m_connect_waiters, {})) {
        waiter->notify_result(nullptr);
    }

    Error<DnsError> error = co_await m_http_conn->drive_io();
    if (shutdown_guard.expired()) {
        co_return;
    }

    co_await m_config.loop.co_submit();
    if (shutdown_guard.expired()) {
        co_return;
    }

    close_connection(error);
    co_return;
}

ag::coro::Task<ag::Result<ag::dns::DohUpstream::HttpConnection *, ag::dns::DnsError>>
ag::dns::DohUpstream::establish_connection(HttpConnection *http_conn, SocketAddress peer) {
    std::weak_ptr<bool> shutdown_guard = http_conn->shutdown_guard;

    log_hconn(trace, http_conn, "Connecting to {}...", peer.str());
    std::string_view hostname = m_url.get_hostname(); // was validated during initialization
    Error<DnsError> error = co_await http_conn->establish(std::string(hostname), peer);
    if (shutdown_guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }

    if (error != nullptr) {
        if (error->value() == DnsError::AE_SOCKET_ERROR) {
            m_retry_connection = true;
            m_bootstrapper->remove_resolved(peer); // NOLINT(*-unchecked-optional-access)
        }
        co_return error;
    }
    log_hconn(trace, http_conn, "Connected");
    co_return http_conn;
}

ag::coro::Task<ag::Result<ag::dns::DohUpstream::HttpConnection *, ag::dns::DnsError>>
ag::dns::DohUpstream::establish_any_of_connections(const std::vector<std::unique_ptr<HttpConnection>> &connections, SocketAddress peer) {
    std::vector<Error<DnsError>> errors;

    auto op = parallel::any_of_cond<Result<HttpConnection *, DnsError>>(
            // NOLINTNEXTLINE(*-avoid-reference-coroutine-parameters)
            [&](const Result<HttpConnection *, DnsError> &result) {
                if (result.has_error()) {
                    // NOLINTNEXTLINE(*-pro-bounds-constant-array-index)
                    errors.push_back(result.error());
                    return false;
                }
                return true;
            });
    for (const auto &connection : connections) {
        op.add(establish_connection(connection.get(), peer));
    }
    std::optional http_conn = co_await op;

    if (!http_conn.has_value()) {
        m_retry_connection = std::find_if(errors.begin(), errors.end(), [](auto &error){
            return (error != nullptr && error->value() == DnsError::AE_SOCKET_ERROR);
        }) != errors.end();
        std::string message = "None of the protocols have connected successfully. Errors: ";
        for (auto &error : errors) {
            message += "\n";
            message += error->str();
        }
        co_return make_error(DnsError::AE_HANDSHAKE_ERROR, message);
    }

    m_retry_connection = false;

    log_hconn(dbg, **http_conn, "Selected protocol");
    co_return http_conn.value();
}

ag::coro::Task<ag::dns::Upstream::ExchangeResult> ag::dns::DohUpstream::exchange(
        Millis timeout, const ldns_pkt *request) {
    std::weak_ptr<bool> shutdown_guard = m_shutdown_guard;

    Result stream_id = send_request(request);
    if (stream_id.has_error()) {
        co_return stream_id.error();
    }

    uint16_t query_id = ldns_pkt_id(request);
    log_query(dbg, m_http_conn, query_id, "Assigned stream id: {}", stream_id.value());

    auto result = co_await parallel::any_of<ExchangeResult>(
            wait_for_reply(stream_id.value(), query_id), wait_timeout(m_config.loop, timeout));
    if (shutdown_guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }

    if (result.has_error() && result.error()->value() == DnsError::AE_TIMED_OUT && m_http_conn != nullptr) {
        m_http_conn->reset_stream(stream_id.value());
    }

    m_streams.erase(stream_id.value());
    co_return result;
}

ag::coro::Task<ag::dns::Upstream::ExchangeResult> ag::dns::DohUpstream::wait_for_reply(
        uint64_t stream_id, uint16_t query_id) {
    std::weak_ptr<bool> shutdown_guard = m_shutdown_guard;
    ReplyWaiter &waiter = *m_streams.emplace(stream_id, std::make_unique<ReplyWaiter>(query_id)).first->second;

    ExchangeResult exchange_result;
    while (true) {
        ReplyWaiter::Result await_result = co_await ReplyAwaitable(waiter);
        if (shutdown_guard.expired()) {
            co_return make_error(DnsError::AE_SHUTTING_DOWN);
        }
        if (await_result.has_error()) {
            if (auto node = m_streams.extract(stream_id); !node.empty() && m_http_conn != nullptr) {
                m_http_conn->reset_stream(stream_id);
            }
            exchange_result = make_error(DnsError::AE_EXCHANGE_ERROR, await_result.error());
            goto loop_exit;
        }

        if (auto *response = std::get_if<http::Response>(&await_result.value()); response != nullptr) {
            int status = response->status_code();
            if (status == 200) { // NOLINT(*-magic-numbers)
                continue;
            }
            if (auto node = m_streams.extract(stream_id); !node.empty()) {
                m_http_conn->reset_stream(stream_id);
            }
            exchange_result = make_error(DnsError::AE_EXCHANGE_ERROR, AG_FMT("Bad response status: {}", status));
            goto loop_exit;
        }

        auto reply = std::move(std::get<ldns_pkt_ptr>(await_result.value()));
        ldns_pkt_set_id(reply.get(), query_id);
        exchange_result = std::move(reply);
        goto loop_exit;
    }

loop_exit:
    co_await m_config.loop.co_submit();
    if (shutdown_guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }

    co_return exchange_result;
}

ag::Result<uint64_t, ag::dns::DnsError> ag::dns::DohUpstream::send_request(const ldns_pkt *query) {
    ldns_buffer_ptr buffer{ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY)};
    if (ldns_status status = ldns_pkt2buffer_wire(buffer.get(), query); status != LDNS_STATUS_OK) {
        return make_error(DnsError::AE_ENCODE_ERROR,
                AG_FMT("{} ({})", ldns_get_errorstr_by_id(status), magic_enum::enum_name(status)));
    }

    // https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
    // In order to maximize HTTP cache friendliness, DoH clients using media
    // formats that include the ID field from the DNS message header, such
    // as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS
    // request.
    *ldns_buffer_at(buffer.get(), 0) = 0;
    *ldns_buffer_at(buffer.get(), 1) = 0;

    http::Request request = m_request_template;
    request.path(AG_FMT("{}?dns={}", m_path,
            encode_to_base64(
                    {ldns_buffer_at(buffer.get(), 0), ldns_buffer_position(buffer.get())}, /*url_safe*/ true)));

    log_query(trace, m_http_conn, ldns_pkt_id(query), "Sending request: {}", request);

    Result stream_id = m_http_conn->submit_request(request);
    if (stream_id.has_error()) {
        return make_error(DnsError::AE_INTERNAL_ERROR, stream_id.error());
    }

    if (m_connect_waiters.empty()) {
        if (Error<DnsError> error = m_http_conn->flush(); error != nullptr) {
            m_http_conn->reset_stream(stream_id.value());
            return make_error(DnsError::AE_INTERNAL_ERROR, std::move(error));
        }
    }

    return stream_id;
}

void ag::dns::DohUpstream::close_connection(const Error<DnsError> &error) {
    m_connection_state = ConnectionState::IDLE;
    m_http_conn.reset();
    m_retry_connection = false;
    cancel_all(error);
    cancel_read_timer();
}

void ag::dns::DohUpstream::cancel_all(const Error<DnsError> &error) {
    auto conn_waiters = std::exchange(m_connect_waiters, {});
    auto http_streams = std::exchange(m_streams, {});

    for (auto &[_, waiter] : conn_waiters) {
        waiter->notify_result(error);
    }

    for (auto &[_, waiter] : http_streams) {
        waiter->notify_error(error);
    }
}

void ag::dns::DohUpstream::cancel_read_timer() {
    if (std::optional task = std::exchange(m_read_timer_task, std::nullopt); task.has_value()) {
        m_config.loop.cancel(task.value());
    }
}

void ag::dns::DohUpstream::refresh_read_timer() {
    cancel_read_timer();

    std::weak_ptr<bool> shutdown_guard = m_shutdown_guard;
    m_read_timer_task = m_config.loop.schedule(
            duration_cast<Micros>(2 * m_config.timeout), [this, shutdown_guard = std::move(shutdown_guard)]() {
                if (shutdown_guard.expired()) {
                    return;
                }

                log_upstream(dbg, this, "Resetting stale connection");
                m_read_timer_task.reset();
                close_connection(make_error(DnsError::AE_TIMED_OUT));
            });
}

void ag::dns::DohUpstream::HttpConnection::on_response(void *arg, uint64_t stream_id, http::Response response) {
    auto *self = (HttpConnection *) arg;
    DohUpstream *upstream = self->parent;

    auto iter = upstream->m_streams.find(stream_id);
    if (iter == upstream->m_streams.end()) {
        log_hconn(dbg, self, "Stream not found: {}", stream_id);
        upstream->m_http_conn->reset_stream(stream_id);
        return;
    }

    ReplyWaiter *awaitable = iter->second.get();
    if (g_logger.is_enabled(LOG_LEVEL_TRACE)) {
        log_query(trace, self, awaitable->query_id, "Received response: {}", response);
    } else if (response.status_code() != 200) {
        log_query(dbg, self, awaitable->query_id, "Received non-200 response: {} {}", response.version(),
                response.status_code());
    }

    awaitable->notify_response(std::move(response));
}

void ag::dns::DohUpstream::HttpConnection::on_body(void *arg, uint64_t stream_id, Uint8View chunk) {
    auto *self = (HttpConnection *) arg;
    DohUpstream *upstream = self->parent;

    auto iter = upstream->m_streams.find(stream_id);
    if (iter == upstream->m_streams.end()) {
        log_hconn(dbg, self, "Stream not found: {}", stream_id);
        self->reset_stream(stream_id);
        return;
    }

    ReplyWaiter *awaitable = iter->second.get();
    log_query(trace, self, awaitable->query_id, "Received response body: {} bytes", chunk.length());

    awaitable->reply_buffer.insert(awaitable->reply_buffer.end(), chunk.begin(), chunk.end());
}

void ag::dns::DohUpstream::HttpConnection::on_stream_read_finished(void *arg, uint64_t stream_id) {
    auto *self = (HttpConnection *) arg;
    DohUpstream *upstream = self->parent;

    auto iter = upstream->m_streams.find(stream_id);
    if (iter == upstream->m_streams.end()) {
        log_hconn(dbg, self, "Stream not found: {}", stream_id);
        upstream->m_http_conn->reset_stream(stream_id);
        return;
    }

    ReplyWaiter *awaitable = iter->second.get();
    log_query(trace, self, awaitable->query_id, "Received fin");

    ldns_pkt *reply = nullptr;
    if (ldns_status status = ldns_wire2pkt(&reply, awaitable->reply_buffer.data(), awaitable->reply_buffer.size());
            status != LDNS_STATUS_OK) {
        constexpr size_t MAX_LOG_DUMP_LENGTH = 256;
        log_query(dbg, self, awaitable->query_id, "Failed to decode response: {}{}",
                utils::encode_to_hex({awaitable->reply_buffer.data(),
                        std::min(MAX_LOG_DUMP_LENGTH, awaitable->reply_buffer.size())}),
                (MAX_LOG_DUMP_LENGTH < awaitable->reply_buffer.size()) ? "...<truncated>..." : "");
        awaitable->notify_error(make_error(DnsError::AE_DECODE_ERROR, ldns_get_errorstr_by_id(status)));
        return;
    }

    awaitable->notify_reply(ldns_pkt_ptr{reply});
}

void ag::dns::DohUpstream::HttpConnection::on_stream_closed(void *arg, uint64_t stream_id, Error<DnsError> error) {
    auto *self = (HttpConnection *) arg;
    if (self->parent_shutdown_guard.expired() || self->parent->m_http_conn == nullptr) {
        return;
    }

    DohUpstream *upstream = self->parent;

    auto iter = upstream->m_streams.find(stream_id);
    if (iter == upstream->m_streams.end()) {
        log_hconn(dbg, self, "Stream not found: {}", stream_id);
        self->reset_stream(stream_id);
        return;
    }

    ReplyWaiter *awaitable = iter->second.get();
    awaitable->notify_error(std::move(error));
}

void ag::dns::DohUpstream::HttpConnection::on_close(void *arg, Error<DnsError> error) {
    auto *self = (HttpConnection *) arg;
    DohUpstream *upstream = self->parent;

    std::weak_ptr<bool> shutdown_guard = self->shutdown_guard;
    upstream->m_config.loop.submit(
            [upstream, error = std::move(error), shutdown_guard = std::move(shutdown_guard)]() mutable {
                if (!shutdown_guard.expired()) {
                    upstream->close_connection(error);
                }
            });
}

void ag::dns::DohUpstream::HttpConnection::on_output(void *arg, Uint8View chunk) {
    auto *self = (HttpConnection *) arg;
    DohUpstream *upstream = self->parent;

    if (Error<SocketError> error = self->io->send(chunk); // NOLINT(*-unchecked-optional-access)
            error != nullptr && upstream->m_connection_state != ConnectionState::IDLE) {
        std::weak_ptr<bool> shutdown_guard = self->shutdown_guard;
        upstream->m_config.loop.submit([upstream, e = std::move(error), shutdown_guard = std::move(shutdown_guard)]() {
            if (!shutdown_guard.expired()) {
                upstream->close_connection(make_error(DnsError::AE_EXCHANGE_ERROR, e));
            }
        });
    }
}

ag::dns::DohUpstream::ReplyWaiter::ReplyWaiter(uint16_t query_id)
        : query_id(query_id) {
}

ag::dns::DohUpstream::ReplyWaiter::~ReplyWaiter() {
    if (state != DONE && handle != nullptr) {
        response.reset();
        reply.reset();
        if (error == nullptr) {
            error = make_error(DnsError::AE_SHUTTING_DOWN);
        }
        std::exchange(handle, nullptr).resume();
    }
}

void ag::dns::DohUpstream::ReplyWaiter::notify_response(http::Response r) {
    assert(state == WAITING_RESPONSE_HEADERS);

    if (r.status_code() == 200) { // NOLINT(*-magic-numbers)
        state = WAITING_RESPONSE_BODY;
    } else {
        state = DONE;
    }

    response.emplace(std::move(r));
    handle.resume();
}

void ag::dns::DohUpstream::ReplyWaiter::notify_reply(ldns_pkt_ptr r) {
    if (std::exchange(state, DONE) != WAITING_RESPONSE_BODY) {
        return;
    }

    reply = std::move(r);
    handle.resume();
}

void ag::dns::DohUpstream::ReplyWaiter::notify_error(Error<DnsError> e) {
    if (std::exchange(state, DONE) != DONE) {
        error = std::move(e);
        handle.resume();
    }
}

ag::http::Version ag::dns::DohUpstream::Http2Connection::version() const {
    return http::HTTP_2_0;
}

ag::coro::Task<ag::Error<ag::dns::DnsError>> ag::dns::DohUpstream::Http2Connection::establish(
        std::string hostname, SocketAddress peer) {
    if (io.has_value() || session != nullptr) {
        co_return make_error(DnsError::AE_INTERNAL_ERROR, "Unreachable");
    }

    Error<DnsError> error = co_await connect_socket(std::move(hostname), peer);
    if (error != nullptr) {
        co_return error;
    }

    Result client = http::Http2Client::make(http::Http2Settings{},
            http::Http2Client::Callbacks{
                    .arg = this,
                    .on_response =
                            [](void *arg, uint32_t stream_id, http::Response response) {
                                on_response(arg, stream_id, std::move(response));
                            },
                    .on_body =
                            [](void *arg, uint32_t stream_id, Uint8View chunk) {
                                on_body(arg, stream_id, chunk);
                            },
                    .on_stream_read_finished =
                            [](void *arg, uint32_t stream_id) {
                                on_stream_read_finished(arg, stream_id);
                            },
                    .on_stream_closed =
                            [](void *arg, uint32_t stream_id, nghttp2_error_code error_code) {
                                on_stream_closed(arg, stream_id,
                                        make_error(DnsError::AE_EXCHANGE_ERROR, nghttp2_strerror(error_code)));
                            },
                    .on_close =
                            [](void *arg, nghttp2_error_code error_code) {
                                on_close(arg, make_error(DnsError::AE_EXCHANGE_ERROR, nghttp2_strerror(error_code)));
                            },
                    .on_output = on_output,
                    .on_data_sent =
                            [](void *arg, uint32_t stream_id, size_t n) {
                                auto *self = (Http2Connection *) arg;
                                self->session->consume_stream(stream_id, n);
                            },
            });
    if (client.has_error()) {
        co_return make_error(DnsError::AE_INTERNAL_ERROR, client.error());
    }

    session = std::move(client.value());
    co_return {};
}

ag::Result<uint64_t, ag::dns::DnsError> ag::dns::DohUpstream::Http2Connection::submit_request(
        const http::Request &request) {
    Result stream_id = session->submit_request(request, /*eof=*/true);
    if (stream_id.has_error()) {
        return make_error(DnsError::AE_INTERNAL_ERROR, stream_id.error());
    }
    return stream_id.value();
}

ag::Error<ag::dns::DnsError> ag::dns::DohUpstream::Http2Connection::reset_stream(uint64_t stream_id) {
    if (Error<http::Http2Error> error = session->reset_stream(stream_id, NGHTTP2_CANCEL); error != nullptr) {
        return make_error(DnsError::AE_INTERNAL_ERROR, std::move(error));
    }
    return {};
}

ag::Error<ag::dns::DnsError> ag::dns::DohUpstream::Http2Connection::flush() {
    if (Error<http::Http2Error> error = session->flush(); error != nullptr) {
        return make_error(DnsError::AE_INTERNAL_ERROR, std::move(error));
    }
    return {};
}

ag::coro::Task<ag::Error<ag::dns::DnsError>> ag::dns::DohUpstream::Http2Connection::drive_io() {
    std::weak_ptr<bool> guard = shutdown_guard;
    Error<SocketError> error = co_await io->receive( // NOLINT(*-unchecked-optional-access)
            AioSocket::OnReadCallback{
                    .func = on_socket_read,
                    .arg = this,
            },
            std::nullopt);
    if (guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }
    if (session_error != nullptr) {
        co_return make_error(DnsError::AE_EXCHANGE_ERROR, std::exchange(session_error, nullptr));
    }
    if (error != nullptr) {
        co_return make_error(DnsError::AE_SOCKET_ERROR, std::move(error));
    }

    co_return make_error(DnsError::AE_INTERNAL_ERROR, "Unreachable");
}

ag::coro::Task<ag::Error<ag::dns::DnsError>> ag::dns::DohUpstream::Http2Connection::connect_socket(
        std::string hostname, SocketAddress peer) {
    AioSocket &socket = io.emplace(parent->make_secured_socket(utils::TP_TCP,
            SocketFactory::SecureSocketParameters{
                    .session_cache = &parent->m_tls_session_cache,
                    .server_name = std::move(hostname),
                    .alpn = {&NGHTTP2_PROTO_ALPN[1]},
                    .fingerprints = parent->m_fingerprints,
            }));

    log_hconn(dbg, this, "{}", peer.str());
    std::weak_ptr<bool> guard = shutdown_guard;
    Error<SocketError> err = co_await socket.connect(AioSocket::ConnectParameters{
            .loop = &parent->m_config.loop,
            .peer = peer,
            .timeout = parent->m_config.timeout,
    });
    if (guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }
    if (err != nullptr) {
        io.reset();
        co_return make_error(DnsError::AE_SOCKET_ERROR, err);
    }

    co_return {};
}

bool ag::dns::DohUpstream::Http2Connection::on_socket_read(void *arg, Uint8View data) {
    auto *self = (Http2Connection *) arg;
    DohUpstream *upstream = self->parent;

    if (upstream->m_read_timer_task.has_value()) {
        upstream->refresh_read_timer();
    }

    if (Result r = self->session->input(data); r.has_error()) {
        self->session_error = make_error(DnsError::AE_INTERNAL_ERROR, r.error());
        return false;
    }
    if (Error<http::Http2Error> error = self->session->flush(); error != nullptr) {
        self->session_error = make_error(DnsError::AE_INTERNAL_ERROR, std::move(error));
        return false;
    }
    return true;
}

ag::http::Version ag::dns::DohUpstream::Http3Connection::version() const {
    return http::HTTP_3_0;
}

ag::coro::Task<ag::Error<ag::dns::DnsError>> ag::dns::DohUpstream::Http3Connection::establish(
        std::string hostname, SocketAddress peer) {
    if (io.has_value() || session != nullptr) {
        co_return make_error(DnsError::AE_INTERNAL_ERROR, "Unreachable");
    }

    bssl::UniquePtr<SSL_CTX> ssl_ctx{SSL_CTX_new(TLS_client_method())};
    if (ssl_ctx == nullptr) {
        co_return make_error(DnsError::AE_INTERNAL_ERROR, ERR_error_string(ERR_get_error(), nullptr));
    }
    SSL_CTX_set_min_proto_version(ssl_ctx.get(), TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx.get(), TLS1_3_VERSION);
    SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_cert_verify_callback(ssl_ctx.get(), on_certificate_verify, this);
    TlsSessionCache::prepare_ssl_ctx(ssl_ctx.get());
    if (0 != ngtcp2_crypto_boringssl_configure_client_context(ssl_ctx.get())) {
        co_return make_error(DnsError::AE_INTERNAL_ERROR, "Couldn't configure SSL object for QUIC");
    }

    bssl::UniquePtr<SSL> ssl(SSL_new(ssl_ctx.get()));
    static constexpr std::string_view ALPN = NGHTTP3_ALPN_H3;
    if (0 != SSL_set_alpn_protos(ssl.get(), (uint8_t *) ALPN.data(), ALPN.size())) {
        co_return make_error(DnsError::AE_INTERNAL_ERROR, "Couldn't configure ALPN");
    }

    SSL_set_tlsext_host_name(ssl.get(), hostname.c_str());
    parent->m_tls_session_cache.prepare_ssl(ssl.get());
    if (SslSessionPtr ssl_session = parent->m_tls_session_cache.get_session()) {
        log_hconn(dbg, this, "Using a cached TLS session");
        SSL_set_session(ssl.get(), ssl_session.get()); // UpRefs the session
    } else {
        log_hconn(trace, this, "No cached TLS sessions available");
    }
    SSL_set_connect_state(ssl.get());

    if (Error<DnsError> error = co_await connect_socket(std::move(hostname), peer); error != nullptr) {
        co_return error;
    }

    Result client = http::Http3Client::connect(http::Http3Settings{},
            http::Http3Client::Callbacks{
                    .arg = this,
                    .on_handshake_completed = on_handshake_completed,
                    .on_response = on_response,
                    .on_body = on_body,
                    .on_stream_read_finished = on_stream_read_finished,
                    .on_stream_closed =
                            [](void *arg, uint64_t stream_id, int err) {
                                on_stream_closed(arg, stream_id,
                                        make_error(DnsError::AE_EXCHANGE_ERROR, AG_FMT("Stream closed: 0x{:x}", err)));
                            },
                    .on_close =
                            [](void *arg, uint64_t err) {
                                on_close(arg,
                                        make_error(DnsError::AE_EXCHANGE_ERROR, AG_FMT("Session closed: 0x{:x}", err)));
                            },
                    .on_output =
                            [](void *arg, const http::QuicNetworkPath &, Uint8View chunk) {
                                on_output(arg, chunk);
                            },
                    .on_data_sent =
                            [](void *arg, uint64_t stream_id, size_t n) {
                                auto *self = (Http3Connection *) arg;
                                self->session->consume_stream(stream_id, n);
                            },
                    .on_expiry_update = on_expiry_update,
            },
            http::QuicNetworkPath{
                    .local = local.c_sockaddr(),
                    .local_len = local.c_socklen(),
                    .remote = remote.c_sockaddr(),
                    .remote_len = remote.c_socklen(),
            },
            std::move(ssl));
    if (client.has_error()) {
        co_return make_error(DnsError::AE_INTERNAL_ERROR, client.error());
    }
    session = std::move(client.value());
    state = State::HANDSHAKING;

    if (Error<http::Http3Error> error = session->flush(); error != nullptr) {
        co_return make_error(DnsError::AE_INTERNAL_ERROR, std::move(error));
    }

    std::weak_ptr<bool> guard = shutdown_guard;
    if (Error<DnsError> error = co_await drive_io(); error != nullptr) {
        co_return make_error(DnsError::AE_HANDSHAKE_ERROR, std::move(error));
    }
    if (guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }

    co_return {};
}

ag::Result<uint64_t, ag::dns::DnsError> ag::dns::DohUpstream::Http3Connection::submit_request(
        const http::Request &request) {
    Result stream_id = session->submit_request(request, /*eof=*/true);
    if (stream_id.has_error()) {
        return make_error(DnsError::AE_INTERNAL_ERROR, stream_id.error());
    }
    return stream_id.value();
}

ag::Error<ag::dns::DnsError> ag::dns::DohUpstream::Http3Connection::reset_stream(uint64_t stream_id) {
    if (Error<http::Http3Error> error = session->reset_stream(stream_id, NGHTTP3_H3_REQUEST_CANCELLED);
            error != nullptr) {
        return make_error(DnsError::AE_INTERNAL_ERROR, std::move(error));
    }
    return {};
}

ag::Error<ag::dns::DnsError> ag::dns::DohUpstream::Http3Connection::flush() {
    if (Error<http::Http3Error> error = session->flush(); error != nullptr) {
        return make_error(DnsError::AE_INTERNAL_ERROR, std::move(error));
    }
    return {};
}

ag::coro::Task<ag::Error<ag::dns::DnsError>> ag::dns::DohUpstream::Http3Connection::drive_io() {
    std::weak_ptr<bool> guard = shutdown_guard;

    State last_state = state;
    Error<SocketError> error = co_await io->receive( // NOLINT(*-unchecked-optional-access)
            AioSocket::OnReadCallback{
                    .func = on_socket_read,
                    .arg = this,
            },
            std::nullopt);

    if (guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }
    if (session_error != nullptr) {
        co_return make_error(DnsError::AE_EXCHANGE_ERROR, std::exchange(session_error, nullptr));
    }
    if (error != nullptr) {
        co_return make_error(DnsError::AE_SOCKET_ERROR, std::move(error));
    }

    if (last_state == State::HANDSHAKING && state == State::CONNECTED) {
        co_return {};
    }

    co_return make_error(DnsError::AE_INTERNAL_ERROR, "Unreachable");
}

ag::coro::Task<ag::Error<ag::dns::DnsError>> ag::dns::DohUpstream::Http3Connection::connect_socket(
        std::string, SocketAddress peer) {
    AioSocket &socket = io.emplace(parent->make_socket(utils::TP_UDP));

    log_hconn(dbg, this, "{}", peer.str());
    std::weak_ptr<bool> guard = shutdown_guard;
    Error<SocketError> err = co_await socket.connect(AioSocket::ConnectParameters{
            .loop = &parent->m_config.loop,
            .peer = peer,
    });
    if (guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }
    if (err != nullptr) {
        io.reset();
        co_return make_error(DnsError::AE_SOCKET_ERROR, err);
    }

    // NOLINTNEXTLINE(*-unchecked-optional-access)
    if (std::optional bound_addr = utils::get_local_address(socket.get_underlying()->get_fd().value());
            bound_addr.has_value()) {
        local = bound_addr.value();
    }
    remote = peer;
    log_hconn(trace, this, "Network path: {} -> {}", local.str(), remote.str());

    co_return {};
}

void ag::dns::DohUpstream::Http3Connection::on_handshake_completed(void *arg) {
    auto *self = (Http3Connection *) arg;
    self->state = State::CONNECTED;
}

void ag::dns::DohUpstream::Http3Connection::on_expiry_update(void *arg, ag::Nanos period) {
    auto *self = (Http3Connection *) arg;
    std::weak_ptr<bool> guard = self->shutdown_guard;
    assert(!guard.expired());

    log_hconn(trace, self, "{}", period);

    if (self->expiry_task.has_value()) {
        self->loop.cancel(self->expiry_task.value());
    }

    self->expiry_task =
            self->loop.schedule(duration_cast<Micros>(period), [self, guard]() {
                if (guard.expired()) {
                    return;
                }
                if (auto error = self->handle_expiry()) {
                    if (!self->parent_shutdown_guard.expired() && self->parent->m_http_conn.get() == self) {
                        self->parent->close_connection(error);
                    }
                }
            });
}

int ag::dns::DohUpstream::Http3Connection::on_certificate_verify(X509_STORE_CTX *ctx, void *arg) {
    auto *self = (Http3Connection *) arg;
    DohUpstream *upstream = self->parent;

    const CertificateVerifier *verifier = upstream->m_config.socket_factory->get_certificate_verifier();
    if (verifier == nullptr) {
        log_hconn(dbg, self, "Cannot verify certificate due to verifier is not set");
        return 0;
    }

    std::string_view hostname = upstream->m_url.get_hostname(); // was validated during initialization
    if (auto err = verifier->verify(ctx, hostname, upstream->m_fingerprints)) {
        log_hconn(dbg, self, "Failed to verify certificate: {}", *err);
        return 0;
    }

    log_hconn(trace, self, "Verified successfully");

    return 1;
}

bool ag::dns::DohUpstream::Http3Connection::on_socket_read(void *arg, Uint8View data) {
    auto *self = (Http3Connection *) arg;
    DohUpstream *upstream = self->parent;

    if (upstream->m_read_timer_task.has_value()) {
        upstream->refresh_read_timer();
    }

    State last_state = self->state;
    if (Error<http::Http3Error> error = self->session->input(
                http::QuicNetworkPath{
                        .local = self->local.c_sockaddr(),
                        .local_len = self->local.c_socklen(),
                        .remote = self->remote.c_sockaddr(),
                        .remote_len = self->remote.c_socklen(),
                },
                data);
            error != nullptr) {
        self->session_error = make_error(DnsError::AE_INTERNAL_ERROR, std::move(error));
        return false;
    }
    if (Error<http::Http3Error> error = self->session->flush(); error != nullptr) {
        self->session_error = make_error(DnsError::AE_INTERNAL_ERROR, std::move(error));
        return false;
    }
    return last_state != State::HANDSHAKING || self->state != State::CONNECTED;
}
ag::Error<ag::dns::DnsError> ag::dns::DohUpstream::Http3Connection::handle_expiry() {
    log_hconn(trace, this, "Handling expiry timer");
    if (Error<http::Http3Error> error = this->session->handle_expiry(); error != nullptr) {
        if ((int) error->value() == NGTCP2_ERR_IDLE_CLOSE) {
            log_hconn(dbg, this, "Closing idle connection");
            return make_error(DnsError::AE_TIMED_OUT);
        }
        log_hconn(dbg, this, "Connection timer handling error: {}", error->str());
        return make_error(DnsError::AE_SOCKET_ERROR, error);
    }
    if (Error<DnsError> error = this->flush(); error != nullptr) {
        log_hconn(dbg, this, "Connection timer handling error: {}", error->str());
        return error;
    }
    return {};
}
