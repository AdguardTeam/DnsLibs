#include <cassert>
#include <magic_enum/magic_enum.hpp>
#include <openssl/rand.h>

#ifdef __linux__
#include <time.h>
#endif

#ifdef __MACH__
#include <sys/sysctl.h>
#include <sys/types.h>
#endif

#include "common/clock.h"
#if defined _WIN32 && !defined __clang__
#pragma optimize( "", off )
#endif
#include "common/parallel.h"
#if defined _WIN32 && !defined __clang__
#pragma optimize( "", on )
#endif
#include "common/time_utils.h"
#include "dns/upstream/upstream.h"

#include "upstream_doq.h"

using namespace std::chrono;

namespace ag::dns {

static constexpr std::string_view DQ_ALPNS[] = {DoqUpstream::RFC9250_ALPN};
static constexpr int KEEPALIVE_INTERVAL_SEC = 30;
static constexpr int LOCAL_IDLE_TIMEOUT_SEC = 180;
static constexpr int MAX_PKTLEN_IPV6 = 1232;
static constexpr size_t QUIC_PACKET_TRACE_BUFSIZE = 2048;

#undef NEVER
#define NEVER (UINT64_MAX / 2)

#define tracelog_id(l_, pkt_, fmt_, ...) tracelog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)

std::atomic_int64_t DoqUpstream::m_next_request_id{1};

DoqUpstream::Buffer::Buffer(const uint8_t *data, size_t datalen)
        : buf{data, data + datalen}
        , tail(datalen) {
}

DoqUpstream::Buffer::Buffer(size_t datalen)
        : buf(datalen)
        , tail(0) {
}

bool DoqUpstream::ConnectionState::is_peer_selected() const {
    return std::holds_alternative<std::unique_ptr<SocketContext>>(this->info);
}

std::unique_ptr<DoqUpstream::SocketContext> DoqUpstream::ConnectionState::extract_socket(SocketContext *ctx) {
    auto *initial_info = std::get_if<ConnectionHandshakeInitialInfo>(&this->info);
    if (initial_info == nullptr) {
        return nullptr;
    }

    auto it = std::find_if(initial_info->sockets.begin(), initial_info->sockets.end(), [ctx](const auto &i) {
        return i.get() == ctx;
    });
    if (it == initial_info->sockets.end()) {
        return nullptr;
    }

    if (initial_info->last_connected_socket == ctx) {
        initial_info->last_connected_socket = nullptr;
    }

    auto out = std::move(*it);
    initial_info->sockets.erase(it);
    return out;
}

DoqUpstream::DoqUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config,
        std::vector<CertFingerprint> fingerprints)
        : Upstream(opts, config)
        , m_max_pktlen{MAX_PKTLEN_IPV6}
        , m_quic_version{NGTCP2_PROTO_VER_V1}
        , m_send_buf(m_max_pktlen)
        , m_req_idle_timer{Uv<uv_timer_t>::create_with_parent(this)}
        , m_handshake_timer(Uv<uv_timer_t>::create_with_parent(this))
        , m_retransmit_timer(Uv<uv_timer_t>::create_with_parent(this))
        , m_static_secret{0}
        , m_tls_session_cache(opts.address)
        , m_shutdown_guard{std::make_shared<bool>(true)}
        , m_fingerprints(std::move(fingerprints)) {
    uv_timer_init(config.loop.handle(), m_req_idle_timer->raw());
    uv_timer_init(config.loop.handle(), m_handshake_timer->raw());
    uv_timer_init(config.loop.handle(), m_retransmit_timer->raw());
}

DoqUpstream::~DoqUpstream() {
    disconnect("Destructor");
}

static ngtcp2_encryption_level from_ssl_encryption_level(enum ssl_encryption_level_t ossl_level) {
#ifdef OPENSSL_IS_BORINGSSL
    return ngtcp2_crypto_boringssl_from_ssl_encryption_level(ossl_level);
#else
    return ngtcp2_crypto_quictls_from_ossl_encryption_level(ossl_level);
#endif
}


#if BORINGSSL_API_VERSION < 10
int DoqUpstream::set_encryption_secrets(SSL *ssl, enum ssl_encryption_level_t ossl_level, const uint8_t *read_secret,
        const uint8_t *write_secret, size_t secret_len) {
    auto doq = static_cast<DoqUpstream *>(SSL_get_app_data(ssl));
    if (0 != doq->on_key(from_ssl_encryption_level(ossl_level), read_secret, write_secret, secret_len)) {
        return 0;
    }
    return 1;
}
#else
int DoqUpstream::set_rx_secret(SSL *ssl, enum ssl_encryption_level_t ossl_level, const SSL_CIPHER *cipher,
        const uint8_t *read_secret, size_t secret_len) {
    auto doq = static_cast<DoqUpstream *>(SSL_get_app_data(ssl));
    if (0 != doq->on_key(
                    ngtcp2_crypto_boringssl_from_ssl_encryption_level(ossl_level), read_secret, nullptr, secret_len)) {
        return 0;
    }
    return 1;
}
int DoqUpstream::set_tx_secret(SSL *ssl, enum ssl_encryption_level_t ossl_level, const SSL_CIPHER *cipher,
        const uint8_t *write_secret, size_t secret_len) {
    auto doq = static_cast<DoqUpstream *>(SSL_get_app_data(ssl));
    if (0
            != doq->on_key(
                    ngtcp2_crypto_boringssl_from_ssl_encryption_level(ossl_level), nullptr, write_secret, secret_len)) {
        return 0;
    }
    return 1;
}
#endif /** else of BORINGSSL_API_VERSION < 10 */

int DoqUpstream::add_handshake_data(SSL *ssl, enum ssl_encryption_level_t ossl_level, const uint8_t *data, size_t len) {
    auto doq = static_cast<DoqUpstream *>(SSL_get_app_data(ssl));
    doq->write_client_handshake(from_ssl_encryption_level(ossl_level), data, len);
    return 1;
}

int DoqUpstream::flush_flight(SSL * /*ssl*/) {
    return 1;
}

static int alert_from_verify_result(long result) {
    switch (result) {
    case X509_V_ERR_CERT_CHAIN_TOO_LONG:
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    case X509_V_ERR_INVALID_CA:
    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    case X509_V_ERR_UNABLE_TO_GET_CRL:
    case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        return SSL_AD_UNKNOWN_CA;

    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
    case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
    case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
    case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
    case X509_V_ERR_CERT_UNTRUSTED:
    case X509_V_ERR_CERT_REJECTED:
    case X509_V_ERR_HOSTNAME_MISMATCH:
    case X509_V_ERR_EMAIL_MISMATCH:
    case X509_V_ERR_IP_ADDRESS_MISMATCH:
        return SSL_AD_BAD_CERTIFICATE;

    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    case X509_V_ERR_CRL_SIGNATURE_FAILURE:
        return SSL_AD_DECRYPT_ERROR;

    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_CRL_HAS_EXPIRED:
    case X509_V_ERR_CRL_NOT_YET_VALID:
        return SSL_AD_CERTIFICATE_EXPIRED;

    case X509_V_ERR_CERT_REVOKED:
        return SSL_AD_CERTIFICATE_REVOKED;

    case X509_V_ERR_UNSPECIFIED:
    case X509_V_ERR_OUT_OF_MEM:
    case X509_V_ERR_INVALID_CALL:
    case X509_V_ERR_STORE_LOOKUP:
        return SSL_AD_INTERNAL_ERROR;

    case X509_V_ERR_APPLICATION_VERIFICATION:
        return SSL_AD_HANDSHAKE_FAILURE;

    case X509_V_ERR_INVALID_PURPOSE:
        return SSL_AD_UNSUPPORTED_CERTIFICATE;

    default:
        return SSL_AD_CERTIFICATE_UNKNOWN;
    }
}

int DoqUpstream::send_alert(SSL *ssl, enum ssl_encryption_level_t /*level*/, uint8_t alert) {
    auto doq = (DoqUpstream *) SSL_get_app_data(ssl);
    errlog(doq->m_log, "SSL error ({}), sending alert", alert);

    auto res = alert_from_verify_result(alert);
    if (res == SSL_AD_BAD_CERTIFICATE || res == SSL_AD_CERTIFICATE_EXPIRED || res == SSL_AD_CERTIFICATE_REVOKED
            || res == SSL_AD_UNSUPPORTED_CERTIFICATE || res == SSL_AD_CERTIFICATE_UNKNOWN) {
        ngtcp2_conn_set_tls_error(doq->m_conn, res);
    }

    return 0;
}

static auto quic_method = SSL_QUIC_METHOD {
#if BORINGSSL_API_VERSION < 10
    DoqUpstream::set_encryption_secrets,
#else
    DoqUpstream::set_rx_secret, DoqUpstream::set_tx_secret,
#endif
            DoqUpstream::add_handshake_data, DoqUpstream::flush_flight, DoqUpstream::send_alert,
};

void DoqUpstream::retransmit_cb(uv_timer_t *timer) {
    auto doq = static_cast<DoqUpstream *>(Uv<uv_timer_t>::parent_from_data(timer->data));
    tracelog(doq->m_log, "{}(): ...", __func__);
    if (doq->m_state == STOP) {
        return;
    }

    if (int ret = doq->handle_expiry(); ret != 0) {
        if (ret == NGTCP2_ERR_IDLE_CLOSE) {
            doq->disconnect("Idle timeout");
        } else {
            doq->disconnect(AG_FMT("Handling expiry error: {}", ngtcp2_strerror(ret)));
        }
        return;
    }

    if (int ret = doq->on_write(); ret != NETWORK_ERR_OK) {
        doq->disconnect(AG_FMT("Retransmission error ({})", ret));
    }
}

void DoqUpstream::short_timeout_timer_cb(uv_timer_t *timer) {
    auto doq = static_cast<DoqUpstream *>(Uv<uv_timer_t>::parent_from_data(timer->data));
    doq->disconnect("Short timeout timer expired");
}

void DoqUpstream::handshake_timer_cb(uv_timer_t *timer) {
    auto doq = static_cast<DoqUpstream *>(Uv<uv_timer_t>::parent_from_data(timer->data));
    // also stop idle timer
    uv_timer_stop(doq->m_req_idle_timer->raw());
    doq->disconnect("Handshake timer expired");
}

void DoqUpstream::send_requests() {
    for (auto &[id, req] : m_requests) {
        if (req.is_onfly) {
            continue;
        }

        int64_t stream_id = -1;
        if (auto rv = ngtcp2_conn_open_bidi_stream(m_conn, &stream_id, nullptr); rv != 0) {
            if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
                dbglog(m_log, "Max streams exhausted: {}", ngtcp2_strerror(rv));
                break;
            }
            disconnect(AG_FMT("Failed to open a new stream: {}", ngtcp2_strerror(rv)));
            return;
        }

        Stream &stream = m_streams[stream_id];
        stream.request_id = req.request_id;
        stream.send_info.buf.reset(evbuffer_new());
        auto length_prefix = (uint16_t) ldns_buffer_remaining(req.request_buffer.get());
        length_prefix = htons(length_prefix);
        evbuffer_add(stream.send_info.buf.get(), &length_prefix, sizeof(length_prefix));
        evbuffer_add(stream.send_info.buf.get(), ldns_buffer_current(req.request_buffer.get()),
                ldns_buffer_remaining(req.request_buffer.get()));

        m_stream_send_queue.push_back(stream_id);

        tracelog(m_log, "Sending request, id: {}", req.request_id);
        if (int ret = on_write(); ret != NETWORK_ERR_OK) {
            disconnect(AG_FMT("Sending request error: {}, id: {}", ret, id));
            return;
        }

        req.is_onfly = true;
    }

    update_req_idle_timer();
}

Error<Upstream::InitError> DoqUpstream::init() {
    auto error = this->init_url_port(/*allow_creds*/ false, /*allow_path*/ false, DEFAULT_DOQ_PORT, /*host_to_lowercase*/ false);
    if (error) {
        return error;
    }

    if (!std::holds_alternative<std::monostate>(m_options.resolved_server_ip)) {
        m_server_addresses.emplace_back(m_options.resolved_server_ip, DEFAULT_DOQ_PORT);
    }

    if (m_server_addresses.empty()) {
        if (m_options.bootstrap.empty() && !SocketAddress(m_url.get_hostname(), m_port).valid()) {
            return make_error(InitError::AE_EMPTY_BOOTSTRAP);
        }
        Bootstrapper::Params bootstrapper_params = {
                .address_string = m_url.get_hostname(),
                .default_port = m_port,
                .bootstrap = m_options.bootstrap,
                .timeout = m_config.timeout,
                .upstream_config = m_config,
                .outbound_interface = m_options.outbound_interface,
        };
        m_bootstrapper = std::make_unique<Bootstrapper>(bootstrapper_params);
        if (auto err = m_bootstrapper->init()) {
            return make_error(InitError::AE_BOOTSTRAPPER_INIT_FAILED, err);
        }
    }

    m_callbacks = ngtcp2_callbacks{
            ngtcp2_crypto_client_initial_cb,
            nullptr, // recv_client_initial
            recv_crypto_data,
            nullptr, // handshake_completed,
            version_negotiation,
            ngtcp2_crypto_encrypt_cb,
            ngtcp2_crypto_decrypt_cb,
            ngtcp2_crypto_hp_mask,
            recv_stream_data,
            acked_stream_data_offset, // acked_stream_data_offset,
            nullptr,                  // stream_open
            on_close_stream,
            nullptr, // recv_stateless_reset
            ngtcp2_crypto_recv_retry_cb,
            nullptr, // extend_max_streams_bidi,
            nullptr, // extend_max_streams_uni
            on_rand, // rand,
            get_new_connection_id,
            nullptr, // remove_connection_id,
            update_key,
            nullptr, // path_validation,
            nullptr, // select_preferred_address,
            nullptr, // stream_reset
            nullptr, // extend_max_remote_streams_bidi,
            nullptr, // extend_max_remote_streams_uni,
            nullptr, // extend_max_stream_data,
            nullptr, // dcid_status
            handshake_confirmed,
            nullptr, // recv_new_token,
            ngtcp2_crypto_delete_crypto_aead_ctx_cb,
            ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
            nullptr, // recv_datagram
            nullptr, // ack_datagram
            nullptr, // lost_datagram
            ngtcp2_crypto_get_path_challenge_data_cb,
            nullptr, // stream_stop_sending
            ngtcp2_crypto_version_negotiation_cb,
    };

    m_remote_addr_empty = SocketAddress("::", m_port);

    if (int ret = init_ssl_ctx(); ret != 0) {
        return make_error(InitError::AE_SSL_CONTEXT_INIT_FAILED);
    }

    return {};
}

coro::Task<Upstream::ExchangeResult> DoqUpstream::exchange(const ldns_pkt *request, const DnsMessageInfo *) {
    std::weak_ptr<bool> guard = m_shutdown_guard;
    if (m_server_addresses.empty()) {
        Bootstrapper::ResolveResult bootstrapper_res = co_await m_bootstrapper->get();
        if (guard.expired()) {
            co_return make_error(DnsError::AE_SHUTTING_DOWN);
        }
        if (bootstrapper_res.error) {
            warnlog(m_log, "Bootstrapper hasn't results");
            co_return make_error(DnsError::AE_BOOTSTRAP_ERROR, bootstrapper_res.error);
        }

        m_server_addresses.assign(bootstrapper_res.addresses.begin(), bootstrapper_res.addresses.end());
    }

    ldns_buffer *buffer = ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY);
    uint16_t original_req_id = ldns_pkt_id(request);
    ldns_status status = ldns_pkt2buffer_wire(buffer, request);
    if (status != LDNS_STATUS_OK) {
        assert(0);
        co_return make_error(DnsError::AE_ENCODE_ERROR, ldns_get_errorstr_by_id(status));
    }
    ldns_buffer_flip(buffer);
    memset(ldns_buffer_current(buffer), '\0', sizeof(original_req_id));

    int64_t request_id = m_next_request_id++;
    Request &req = m_requests[request_id];
    req.request_id = request_id;
    req.request_buffer.reset(buffer);
    tracelog_id(m_log, request, "Creation new request, id: {}, connection state: {}", request_id,
            magic_enum::enum_name(m_state.load()));

    if (m_state != RUN) {
        int res = this->reinit();
        if (res != NETWORK_ERR_HANDSHAKE_RUN && res != NETWORK_ERR_OK) {
            disconnect(AG_FMT("Reinit failed ({})", res));
        }
    } else {
        this->send_requests();
    }

    auto await_result = [](Request &req) {
        struct AwaitResult { // NOLINT: coroutine awaitable
            Request &req;
            bool await_ready() const {
                return req.completed;
            }
            void await_suspend(std::coroutine_handle<> h) {
                req.caller = h;
            }
            std::cv_status await_resume() {
                return std::cv_status::no_timeout;
            }
        };
        return AwaitResult{.req = req};
    };
    auto await_timeout = [](EventLoop &loop, auto timeout) -> coro::Task<std::cv_status> {
        co_await loop.co_sleep(timeout);
        co_return std::cv_status::timeout;
    };
    auto timeout = co_await parallel::any_of<std::cv_status>(
            await_result(req),
            await_timeout(config().loop, m_config.timeout)
    );
    if (guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }
    ldns_pkt *res = req.reply_pkt.release();
    auto err = req.error;
    tracelog_id(m_log, request, "Erase request, id: {}, connection state: {}", request_id,
            magic_enum::enum_name(m_state.load()));
    m_requests.erase(request_id);

    if (timeout == std::cv_status::timeout) {
        co_return make_error(DnsError::AE_TIMED_OUT);
    }

    if (res != nullptr) {
        ldns_pkt_set_id(res, original_req_id);
        co_return ldns_pkt_ptr{res};
    }

    co_return err ? err : make_error(DnsError::AE_RESPONSE_PACKET_TOO_SHORT);
}

void DoqUpstream::on_socket_connected(void *arg) {
    auto *ctx = (SocketContext *) arg;
    DoqUpstream *self = ctx->upstream;

    const SocketAddress &peer = ctx->socket->get_peer();
    tracelog(self->m_log, "{}(): {}", __func__, peer.str());

    auto *info = std::get_if<ConnectionHandshakeInitialInfo>(&self->m_conn_state.info);
    if (info == nullptr) {
        dbglog(self->m_log, "Invalid server connection state (peer selected={}) on socket connected ({}) event",
                self->m_conn_state.is_peer_selected(), peer.str());
        assert(0);
        self->disconnect("Internal error");
        return;
    }

    if (int r; self->m_conn == nullptr && NETWORK_ERR_OK != (r = self->init_quic_conn(ctx->socket.get()))) {
        self->disconnect("Internal error");
        return;
    }

    info->last_connected_socket = ctx;
    if (int r = self->on_write(); r != NETWORK_ERR_OK) {
        dbglog(self->m_log, "Failed to send packet to {}: {}", peer.str(), r);
        goto fail;
    }

    return;

fail:
    self->disqualify_server_address(peer);
    auto drop = self->m_conn_state.extract_socket(ctx);
    // if the peer is not yet selected and we have some pending endpoints,
    // do not disconnect immediately - wait for other ones
    if (info->sockets.empty()) {
        self->disconnect("Failed to handshake with any peer");
    }
}

void DoqUpstream::on_socket_read(void *arg, Uint8View data) {
    auto *ctx = (SocketContext *) arg;
    DoqUpstream *self = ctx->upstream;
    tracelog(self->m_log, "{}(): Read {} bytes from {}", __func__, data.size(), ctx->socket->get_peer().str());

    std::string disconnect_reason;
    if (int ret = self->feed_data(data); ret != NETWORK_ERR_OK) {
        if (ret == NGTCP2_ERR_CALLBACK_FAILURE) {
            // Shutting down
            return;
        }
        if (ret == NGTCP2_ERR_RECV_VERSION_NEGOTIATION) {
            self->disconnect("Switching QUIC version");
            self->reinit();
            return;
        }

        if (!self->m_conn_state.is_peer_selected()) {
            auto drop = self->m_conn_state.extract_socket(ctx);
        }

        disconnect_reason = AG_FMT("Reading error ({})", ret);
        goto fail;
    }

    if (!self->m_conn_state.is_peer_selected()) {
        auto ctx_ = self->m_conn_state.extract_socket(ctx);
        if (ctx_ == nullptr) {
            errlog(self->m_log, "Socket context is not found in the list");
            self->disconnect("Internal error");
            assert(0);
            return;
        }

        // we got a candidate for the further communication
        self->m_conn_state.info = std::move(ctx_);
    }

    if (int ret = self->on_write(); ret != NETWORK_ERR_OK) {
        dbglog(self->m_log, "Failed to write data: {}", ret);
        disconnect_reason = AG_FMT("Write failed ({})", ret);
        goto fail;
    }

    return;

fail:
    // if the peer is not yet selected, and we have some pending endpoints,
    // do not disconnect immediately - wait for other ones
    if (const ConnectionHandshakeInitialInfo * info; self->m_conn_state.is_peer_selected()
            || nullptr == (info = std::get_if<ConnectionHandshakeInitialInfo>(&self->m_conn_state.info))
            || info->sockets.empty()) {
        self->disconnect(disconnect_reason);
    }
}

void DoqUpstream::on_socket_close(void *arg, Error<SocketError> error) {
    auto *ctx = (SocketContext *) arg;
    DoqUpstream *self = ctx->upstream;

    const SocketAddress &peer = ctx->socket->get_peer();
    if (error) {
        dbglog(self->m_log, "Failed to connect to {}: {}", peer.str(), error->str());
        if (!self->m_conn_state.is_peer_selected()) {
            self->disqualify_server_address(peer);
        }
        if (error->value() == SocketError::AE_CONNECTION_REFUSED) {
            self->m_fatal_error = make_error(DnsError::AE_SOCKET_ERROR, error);
        }
    } else {
        dbglog(self->m_log, "Connection to {} closed", peer.str());
        self->m_fatal_error = nullptr;
    }

    auto drop = self->m_conn_state.extract_socket(ctx);
    // if the peer is not yet selected and we have some pending endpoints,
    // do not disconnect immediately - wait for other ones
    if (const ConnectionHandshakeInitialInfo * info; self->m_conn_state.is_peer_selected()
            || nullptr == (info = std::get_if<ConnectionHandshakeInitialInfo>(&self->m_conn_state.info))
            || info->sockets.empty()) {
        self->disconnect("Connection is closed");
    }
}

int DoqUpstream::on_write() {
    if (m_send_buf.size() > 0) {
        if (auto rv = send_packet(); rv != NETWORK_ERR_OK) {
            disconnect("Resending packet failed");
            return rv;
        }
    }

    assert(m_send_buf.left() >= m_max_pktlen);

    if (auto rv = write_streams(); rv != NETWORK_ERR_OK) {
        schedule_retransmit();
        return rv;
    }

    schedule_retransmit();
    return 0;
}

static int ag_evbuffer_peek_exact(struct evbuffer *buffer, ev_ssize_t len,
                                  struct evbuffer_ptr *start_at,
                                  struct evbuffer_iovec *vec_out, int n_vec) {
    int vec_cnt = evbuffer_peek(buffer, len, start_at, vec_out, n_vec);
    if (vec_cnt < 0) {
        return vec_cnt;
    }
    int idx = 0;
    size_t remaining = len;
    while (idx < vec_cnt && remaining) {
        if (remaining < vec_out[idx].iov_len) {
            vec_out[idx].iov_len = remaining;
        }
        remaining -= vec_out[idx].iov_len;
        idx += 1;
    }
    return idx;
}

/**
 * Peeks first stream data from outbound queue and returns stream id to write this data.
 * @param vec_out Output iovec
 * @param[in,out] n_vec_out Size of output iovec. Modified after call to number of actually used chunks
 * @param eof_out Output variable for eof flag
 */
int64_t DoqUpstream::peek_stream_data(struct evbuffer_iovec *vec_out, int *n_vec_out, bool *eof_out) {
    while (!m_stream_send_queue.empty() && ngtcp2_conn_get_max_data_left(m_conn)) {
        int64_t stream_id = m_stream_send_queue.front();
        auto it = m_streams.find(stream_id);
        if (it == m_streams.end()) {
            m_stream_send_queue.pop_front();
            continue;
        }
        Stream &st = it->second;
        evbuffer *buf = st.send_info.buf.get();
        if (evbuffer_get_length(buf) - st.send_info.read_position == 0) {
            m_stream_send_queue.pop_front();
            continue;
        }
        evbuffer_ptr position = {};
        evbuffer_ptr_set(buf, &position, st.send_info.read_position, EVBUFFER_PTR_SET);
        *n_vec_out = ag_evbuffer_peek_exact(buf, evbuffer_get_length(buf), &position, vec_out, *n_vec_out);
        if (eof_out) {
            *eof_out = true;
        }
        return stream_id;
    }
    return -1;
}

int DoqUpstream::write_streams() {
    ngtcp2_vec vec[2];

    for (;;) {
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

        int vcnt = std::size(vec);
        bool eof = false;
        int64_t stream_id = peek_stream_data((evbuffer_iovec *) vec, &vcnt, &eof);

        if (eof) {
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        }

        ngtcp2_ssize ndatalen;
        ngtcp2_pkt_info pi;

        auto initial_ts = get_tstamp();
        tracelog(m_log, "{}(): data={}, wpos={}, buf_size={}, size={}, left={}, max_pktlen={}", __func__,
                (void *) m_send_buf.buf.data(), (void *) m_send_buf.wpos(), m_send_buf.buf.size(), m_send_buf.size(),
                m_send_buf.left(), m_max_pktlen);
        auto nwrite = ngtcp2_conn_writev_stream(m_conn, nullptr, &pi, m_send_buf.wpos(), m_max_pktlen, &ndatalen, flags,
                stream_id, vec, vcnt, initial_ts);

        if (nwrite < 0) {
            switch (nwrite) {
            case NGTCP2_ERR_STREAM_DATA_BLOCKED:
            case NGTCP2_ERR_STREAM_SHUT_WR:
                assert(ndatalen == -1);
                warnlog(m_log, "Can't write stream {} because: {}", stream_id, ngtcp2_strerror(nwrite));
                if (!m_stream_send_queue.empty()) {
                    m_stream_send_queue.pop_front();
                }
                continue;
            case NGTCP2_ERR_WRITE_MORE:
                assert(ndatalen > 0);
                m_streams[stream_id].send_info.read_position += ndatalen;
                continue;
            }
            errlog(m_log, "ngtcp2_conn_write_stream: {}", ngtcp2_strerror(nwrite));
            return NETWORK_ERR_FATAL;
        }

        if (nwrite == 0) {
            return 0;
        }

        if (ndatalen > 0) {
            m_streams[stream_id].send_info.read_position += ndatalen;
        }

        m_send_buf.push(nwrite);

        if (auto rv = send_packet(); rv != NETWORK_ERR_OK) {
            return rv;
        }

        if (m_send_buf.left() == 0) {
            return 0;
        }
    }

    return 0;
}

int DoqUpstream::send_packet(Socket *active_socket, Uint8View data) {
    tracelog(m_log, "Sending {} bytes to {}", data.size(), active_socket->get_peer().str());
    assert(!data.empty());
    auto e = active_socket->send(data);
    if (e) {
        dbglog(m_log, "Failed to send packet: {}", e->str());
    }

    m_send_buf.reset();

    return !e ? NETWORK_ERR_OK : NETWORK_ERR_DROP_CONN;
}

int DoqUpstream::send_packet() {
    Uint8View data = {m_send_buf.rpos(), m_send_buf.size()};
    if (auto *info = std::get_if<ConnectionHandshakeInitialInfo>(&m_conn_state.info);
            info != nullptr && info->last_connected_socket != nullptr) {
        return send_packet(info->last_connected_socket->socket.get(), data);
    }

    if (auto *active_socket = std::get_if<std::unique_ptr<SocketContext>>(&m_conn_state.info)) {
        return send_packet((*active_socket)->socket.get(), data);
    }

    errlog(m_log, "{}(): no socket to send data on", __func__);
    assert(0);
    return NETWORK_ERR_DROP_CONN;
}

int DoqUpstream::connect_to_peers(const std::vector<SocketAddress> &current_addresses) {
    std::vector<std::unique_ptr<SocketContext>> sockets;
    sockets.reserve(current_addresses.size());

    for (auto &address : current_addresses) {
        auto &ctx = sockets.emplace_back(new SocketContext{});
        ctx->upstream = this;
        ctx->socket = this->make_socket(utils::TP_UDP);
        if (auto err = ctx->socket->connect(
                    {&config().loop, address, {on_socket_connected, on_socket_read, on_socket_close, ctx.get()}})) {
            dbglog(m_log, "Failed to start connection to {}: {}", address.str(), err->str());
            disqualify_server_address(address);
            sockets.erase(std::next(sockets.end(), -1));
        }
    }

    if (current_addresses.empty()) {
        dbglog(m_log, "None of the current peers are available");
        return NETWORK_ERR_DROP_CONN;
    }

    m_conn_state.info = ConnectionHandshakeInitialInfo{std::move(sockets)};

    uint64_t pending_ms = uv_timer_get_due_in(m_handshake_timer->raw());
    if (pending_ms == 0) {
        uv_timer_start(m_handshake_timer->raw(), handshake_timer_cb, to_millis(m_config.timeout).count(), 0);
    }
    return NETWORK_ERR_OK;
}

void DoqUpstream::log_quic_packets(void *user_data, const char *format, ...) {
    char buffer[QUIC_PACKET_TRACE_BUFSIZE];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, QUIC_PACKET_TRACE_BUFSIZE, format, args);
    va_end(args);
    auto *doq = (DoqUpstream *) user_data;
    tracelog(doq->m_log, "{}", buffer);
}

int DoqUpstream::init_quic_conn(const Socket *connected_socket) {
    // as for now we don't support the QUIC connection migration it does not matter
    // which address we are using in the path, so just pick the first connected one as the local address
    if (auto fd = connected_socket->get_fd(); !fd.has_value()) {
        dbglog(m_log, "Failed to get underlying descriptor of socket: {}", connected_socket->get_peer().str());
        return -1;
    } else if (auto bound_addr = utils::get_local_address(fd.value()); !bound_addr.has_value()) {
        dbglog(m_log, "Failed to get bound address of socket: {}", connected_socket->get_peer().str());
        return -1;
    } else {
        m_local_addr = bound_addr.value();
    }

    ngtcp2_path path = {{.addr = (sockaddr *) m_local_addr.c_sockaddr(), .addrlen = m_local_addr.c_socklen()},
            {.addr = (sockaddr *) m_remote_addr_empty.c_sockaddr(), .addrlen = m_remote_addr_empty.c_socklen()}};

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
#if 0
    if (ag::Logger::get_log_level() == LOG_LEVEL_TRACE) {
        settings.log_printf = log_quic_packets;
    }
#endif

    ngtcp2_transport_params txparams;
    ngtcp2_transport_params_default(&txparams);

    ag_ngtcp2_settings_default(settings, txparams);

    RAND_bytes(m_static_secret.data(), m_static_secret.size());
    auto generate_cid = [](ngtcp2_cid &cid, size_t len) {
        cid.datalen = len;
        RAND_bytes(cid.data, cid.datalen);
    };
    ngtcp2_cid scid, dcid;
    generate_cid(scid, 17);
    generate_cid(dcid, 18);

    auto rv = ngtcp2_conn_client_new(
            &m_conn, &dcid, &scid, &path, m_quic_version, &m_callbacks, &settings, &txparams, nullptr, this);
    if (rv != 0) {
        errlog(m_log, "Failed to create ngtcp2_conn: {}", ngtcp2_strerror(rv));
        return -1;
    }
    ngtcp2_conn_set_keep_alive_timeout(m_conn, KEEPALIVE_INTERVAL_SEC * NGTCP2_SECONDS);

    if (init_ssl() != 0) {
        errlog(m_log, "Failed to create SSL");
        return -1;
    }
    ngtcp2_conn_set_tls_native_handle(m_conn, m_ssl.get());

    return NETWORK_ERR_OK;
}

int DoqUpstream::init_ssl_ctx() {
    m_ssl_ctx.reset(SSL_CTX_new(TLS_client_method()));
    if (m_ssl_ctx == nullptr) {
        return 1;
    }
    SSL_CTX_set_min_proto_version(m_ssl_ctx.get(), TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(m_ssl_ctx.get(), TLS1_3_VERSION);
    SSL_CTX_set_quic_method(m_ssl_ctx.get(), &quic_method);
    // setup our verifier
    SSL_CTX_set_verify(m_ssl_ctx.get(), SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_cert_verify_callback(m_ssl_ctx.get(), DoqUpstream::ssl_verify_callback, nullptr);
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CTX_set_permute_extensions(m_ssl_ctx.get(), true);
#endif // OPENSSL_IS_BORINGSSL
    TlsSessionCache::prepare_ssl_ctx(m_ssl_ctx.get());
    return 0;
}

int DoqUpstream::init_ssl() {
    m_ssl.reset(SSL_new(m_ssl_ctx.get()));
    if (m_ssl == nullptr) {
        return 1;
    }
    SSL_set_app_data(m_ssl.get(), this);
    if (!SocketAddress(m_url.get_hostname(), 0).valid()) {
        SSL_set_tlsext_host_name(m_ssl.get(), std::string{m_url.get_hostname()}.c_str());
    }
    SSL_set_connect_state(m_ssl.get());
    SSL_set_quic_use_legacy_codepoint(m_ssl.get(), m_quic_version != NGTCP2_PROTO_VER_V1);

    std::string alpn, printable;
    for (auto &dq_alpn : DQ_ALPNS) {
        alpn.push_back(dq_alpn.size());
        alpn.append(dq_alpn);
        printable.push_back(' ');
        printable.append(dq_alpn);
    }
    dbglog(m_log, "Advertised ALPNs:{}", printable);
    SSL_set_alpn_protos(m_ssl.get(), (uint8_t *) alpn.data(), alpn.size());

    m_tls_session_cache.prepare_ssl(m_ssl.get());

    if (SslSessionPtr session = m_tls_session_cache.get_session()) {
        dbglog(m_log, "Using a cached TLS session");
        SSL_set_session(m_ssl.get(), session.get()); // UpRefs the session
    } else {
        dbglog(m_log, "No cached TLS sessions available");
    }

    return 0;
}

void DoqUpstream::write_client_handshake(ngtcp2_encryption_level level, const uint8_t *data, size_t datalen) {
    auto &crypto = m_crypto[level];
    crypto.data.emplace_back(data, datalen);
    auto &buf = crypto.data.back();
    ngtcp2_conn_submit_crypto_data(m_conn, level, buf.rpos(), buf.size());
}

int DoqUpstream::feed_data(Uint8View data) {
    ngtcp2_path path = {{.addr = (sockaddr *) m_local_addr.c_sockaddr(), .addrlen = m_local_addr.c_socklen()},
            {.addr = (sockaddr *) m_remote_addr_empty.c_sockaddr(), .addrlen = m_remote_addr_empty.c_socklen()}};

    auto initial_ts = get_tstamp();

    ngtcp2_pkt_info pi{};
    auto rv = ngtcp2_conn_read_pkt(m_conn, &path, &pi, data.data(), data.size(), initial_ts);

    if (rv != 0 && rv != NGTCP2_ERR_RECV_VERSION_NEGOTIATION) {
        if (rv != NGTCP2_ERR_CALLBACK_FAILURE) {
            dbglog(m_log, "ngtcp2_conn_read_pkt: {}", ngtcp2_strerror(rv));
        }
    }

    return rv;
}

int DoqUpstream::version_negotiation(
        ngtcp2_conn * /*conn*/, const ngtcp2_pkt_hd * /*hd*/, const uint32_t *sv, size_t nsv, void *user_data) {
    auto doq = static_cast<DoqUpstream *>(user_data);
    uint32_t version = 0;
    bool selected = false;
    for (size_t i = 0; i < nsv; i++) {
        if (NGTCP2_PROTO_VER_MIN <= sv[i] && sv[i] <= NGTCP2_PROTO_VER_MAX) {
            selected = true;
            version = std::max(version, sv[i]);
        }
    }
    dbglog(doq->m_log,
            "Version negotiation. Client supported versions: {:#x} to {:#x}, server supported "
            "versions: {}",
            NGTCP2_PROTO_VER_MIN, NGTCP2_PROTO_VER_MAX, std::span<const uint32_t>{sv, sv + nsv});

    if (selected) {
        dbglog(doq->m_log, "Switching from QUIC version {:#x} to negotiated QUIC version {:#x}", doq->m_quic_version,
                version);
        doq->m_quic_version = version;
        return 0;
    }

    dbglog(doq->m_log, "QUIC version can't be negotiated - no common supported QUIC versions with server.");
    return -1;
}

int DoqUpstream::recv_crypto_data(ngtcp2_conn *conn, ngtcp2_encryption_level crypto_level, uint64_t /*offset*/,
        const uint8_t *data, size_t datalen, void *user_data) {

    if (ngtcp2_crypto_read_write_crypto_data(conn, crypto_level, data, datalen) != 0) {
        if (auto err = ngtcp2_conn_get_tls_error(conn); err) {
            auto doq = static_cast<DoqUpstream *>(user_data);
            doq->m_fatal_error = make_error(DnsError::AE_HANDSHAKE_ERROR, SSL_alert_desc_string(err));
        }
        return NGTCP2_ERR_CRYPTO;
    }

    return 0;
}

int DoqUpstream::on_key(
        ngtcp2_encryption_level level, const uint8_t *rx_secret, const uint8_t *tx_secret, size_t secretlen) {
    std::array<uint8_t, 64> rx_key{}, rx_iv{}, rx_hp_key{}, tx_key{}, tx_iv{}, tx_hp_key{};

    std::string direction;
    if (rx_secret) {
        direction += "RX";
        if (ngtcp2_crypto_derive_and_install_rx_key(
                    m_conn, rx_key.data(), rx_iv.data(), rx_hp_key.data(), level, rx_secret, secretlen)
                != 0) {
            return -1;
        }
    }

    if (tx_secret) {
        direction += "TX";
        if (ngtcp2_crypto_derive_and_install_tx_key(
                    m_conn, tx_key.data(), tx_iv.data(), tx_hp_key.data(), level, tx_secret, secretlen)
                != 0) {
            return -1;
        }
    }

    dbglog(m_log, "Crypto {} level: {}", direction, magic_enum::enum_name(level));

    return 0;
}

int DoqUpstream::update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
        ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv, ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
        const uint8_t *current_rx_secret, const uint8_t *current_tx_secret, size_t secretlen, void * /*user_data*/) {

    std::array<uint8_t, 64> rx_key{}, tx_key{};

    if (ngtcp2_crypto_update_key(conn, rx_secret, tx_secret, rx_aead_ctx, rx_key.data(), rx_iv, tx_aead_ctx,
                tx_key.data(), tx_iv, current_rx_secret, current_tx_secret, secretlen)
            != 0) {
        return -1;
    }

    return 0;
}

// NOTE: Use a monotonic clock that is not user-adjustable and doesn't stop when system goes to sleep
ngtcp2_tstamp DoqUpstream::get_tstamp() {
#ifdef __linux__
    static constexpr int64_t NANOS_PER_SEC = 1'000'000'000;
    timespec ts{};
    if (clock_gettime(CLOCK_BOOTTIME, &ts) != -1) {
        return (ts.tv_sec * NANOS_PER_SEC) + ts.tv_nsec;
    }
#endif
    return duration_cast<Nanos>(SteadyClock::now().time_since_epoch()).count();
}

int DoqUpstream::recv_stream_data(ngtcp2_conn * /*conn*/, uint32_t flags, int64_t stream_id, uint64_t /*offset*/,
        const uint8_t *data, size_t datalen, void *user_data, void * /*stream_user_data*/) {

    auto doq = static_cast<DoqUpstream *>(user_data);

    auto st = doq->m_streams.find(stream_id);
    if (st == doq->m_streams.end()) {
        warnlog(doq->m_log, "Stream died");
        return 0;
    }

    std::weak_ptr<bool> shutdown_guard = doq->m_shutdown_guard;
    if (st->second.raw_data.empty() && (flags & NGTCP2_STREAM_DATA_FLAG_FIN)) {
        doq->process_reply(st->second.request_id, {data, datalen});
    } else {
        auto &raw_vec = st->second.raw_data;
        raw_vec.reserve(raw_vec.size() + datalen);
        std::copy(data, data + datalen, std::back_inserter(raw_vec));

        if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
            doq->process_reply(st->second.request_id, {raw_vec.data(), raw_vec.size()});
        }
    }

    return shutdown_guard.expired() ? NGTCP2_ERR_DROP_CONN : 0;
}

int DoqUpstream::get_new_connection_id(
        ngtcp2_conn * /*conn*/, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data) {

    auto doq = (DoqUpstream *) user_data;

    RAND_bytes(cid->data, cidlen);
    cid->datalen = cidlen;
    if (ngtcp2_crypto_generate_stateless_reset_token(
                token, doq->m_static_secret.data(), doq->m_static_secret.size(), cid)
            != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

int DoqUpstream::handshake_confirmed(ngtcp2_conn * /*conn*/, void *data) {

    auto *doq = (DoqUpstream *) data;
    tracelog(doq->m_log, "{}", __func__);
    uv_timer_stop(doq->m_handshake_timer->raw());

    const uint8_t *buf = nullptr;
    uint32_t len = 0;
    SSL_get0_alpn_selected(doq->m_ssl.get(), &buf, &len);
    dbglog(doq->m_log, "Selected ALPN: {}", std::string_view{(char *) buf, len});

    doq->m_state = RUN;
    doq->send_requests();
    return 0;
}

void DoqUpstream::ag_ngtcp2_settings_default(ngtcp2_settings &settings, ngtcp2_transport_params &params) const {
    settings.max_tx_udp_payload_size = m_max_pktlen;
    settings.cc_algo = NGTCP2_CC_ALGO_CUBIC;
    settings.initial_ts = get_tstamp();
    settings.initial_rtt = NGTCP2_DEFAULT_INITIAL_RTT / 2;

    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.initial_max_data = 1 * 1024 * 1024;
    params.initial_max_streams_bidi = 1 * 1024;
    params.initial_max_streams_uni = 0;
    params.max_idle_timeout = LOCAL_IDLE_TIMEOUT_SEC * NGTCP2_SECONDS;
    params.active_connection_id_limit = 7;
}

int DoqUpstream::reinit() {
    if (m_state == HANDSHAKE || m_state == RUN) {
        return NETWORK_ERR_HANDSHAKE_RUN;
    }
    m_state = HANDSHAKE;

    m_streams.clear();
    m_stream_send_queue.clear();

    std::vector<SocketAddress> current_addresses;

    // Getting one ipv6 address
    if (m_config.ipv6_available) {
        for (auto &cur : m_server_addresses) {
            if (cur.is_ipv6()) {
                current_addresses.emplace_back(cur);
                break;
            }
        }
    }

    // Getting one ipv4 address
    for (auto &cur : m_server_addresses) {
        if (cur.is_ipv4()) {
            current_addresses.emplace_back(cur);
            break;
        }
    }

    for (auto &cur : current_addresses) {
        tracelog(m_log, "In this session will use the address: {}", cur.str());
    }

    if (int r = connect_to_peers(current_addresses); r != NETWORK_ERR_OK) {
        assert(0);
        return -1;
    }

    return 0;
}

int DoqUpstream::on_close_stream(ngtcp2_conn * /*conn*/, uint32_t /*flags*/, int64_t stream_id,
        uint64_t /*app_error_code*/, void *user_data, void * /*stream_user_data*/) {

    auto doq = static_cast<DoqUpstream *>(user_data);
    doq->m_streams.erase(stream_id);
    doq->send_requests(); // Send requests blocked by max streams reached.
    return 0;
}

int DoqUpstream::acked_stream_data_offset(ngtcp2_conn * /*conn*/, int64_t stream_id, uint64_t /*offset*/,
        uint64_t datalen, void *user_data, void * /*stream_user_data*/) {

    auto doq = (DoqUpstream *) user_data;
    if (auto it = doq->m_streams.find(stream_id); it != doq->m_streams.end()) {
        auto &stream = it->second;
        evbuffer *buf = stream.send_info.buf.get();
        evbuffer_drain(buf, datalen);
        stream.send_info.read_position -= datalen;
        if (stream.send_info.read_position < 0) {
            errlog(doq->m_log, "read_position={} datalen={}", stream.send_info.read_position, datalen);
        }
        assert(stream.send_info.read_position >= 0);
    }

    return 0;
}

void DoqUpstream::process_reply(int64_t request_id, Uint8View reply) {
    auto node = m_requests.extract(request_id);

    update_req_idle_timer();

    if (node.empty()) {
        return;
    }

    ldns_pkt *pkt = nullptr;
    // Ignore the 2-byte length prefix. We only need the first reply.
    if (reply.size() >= 2) {
        reply.remove_prefix(2);
    }
    ldns_status r = ldns_wire2pkt(&pkt, reply.data(), reply.size());
    if (r != LDNS_STATUS_OK) {
        dbglog(m_log, "Failed to parse reply for [{}]: {}", request_id, magic_enum::enum_name(r));
        pkt = nullptr;
    }
    node.mapped().reply_pkt.reset(pkt);
    node.mapped().complete();
}

void DoqUpstream::disconnect(std::string_view reason) {
    m_state = STOP;

    dbglog(m_log, "Disconnect reason: {}", reason);
    ngtcp2_conn_del(std::exchange(m_conn, nullptr));
    uv_timer_stop(m_handshake_timer->raw());
    uv_timer_stop(m_req_idle_timer->raw());
    uv_timer_stop(m_retransmit_timer->raw());

    m_conn_state.info.emplace<std::monostate>();

    m_ssl.reset();

    std::vector<int64_t> requests_to_complete;
    for (auto &cur : m_requests) {
        tracelog(m_log, "Completing request, id: {}", cur.first);
        cur.second.error = m_fatal_error ? m_fatal_error : make_error(DnsError::AE_CONNECTION_CLOSED);
        requests_to_complete.push_back(cur.first);
    }
    for (int64_t id : requests_to_complete) {
        auto node = m_requests.extract(id);
        if (!node.empty()) {
            node.mapped().complete();
        }
    }
}

int DoqUpstream::handle_expiry() {
    auto now = get_tstamp();
    return ngtcp2_conn_handle_expiry(m_conn, now);
}

void DoqUpstream::schedule_retransmit() {
    auto expiry_ns = ngtcp2_conn_get_expiry(m_conn);
    if (expiry_ns > NEVER) {
        return;
    }
    auto now_ns = get_tstamp();

    Millis ms{0};
    if (expiry_ns > now_ns) {
        Nanos timeout_ns{expiry_ns - now_ns};
        ms = ceil<Millis>(timeout_ns);
    }
    uv_timer_stop(m_retransmit_timer->raw());
    tracelog(m_log, "Next retransmit in {}", ms);
    uv_timer_start(m_retransmit_timer->raw(), retransmit_cb, ms.count(), 0);
}

int DoqUpstream::ssl_verify_callback(X509_STORE_CTX *ctx, void * /*arg*/) {

    SSL *ssl = (SSL *) X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    auto doq = (DoqUpstream *) SSL_get_app_data(ssl);

    const CertificateVerifier *verifier = doq->m_config.socket_factory->get_certificate_verifier();
    if (verifier == nullptr) {
        dbglog(doq->m_log, "Cannot verify certificate due to verifier is not set");
        return 0;
    }

    if (auto err = verifier->verify(ctx, doq->m_url.get_hostname(), doq->m_fingerprints)) {
        dbglog(doq->m_log, "Failed to verify certificate: {}", *err);
        return 0;
    }

    tracelog(doq->m_log, "Verified successfully");

    return 1;
}

void DoqUpstream::disqualify_server_address(const SocketAddress &server_address) {
    for (auto it_serv = m_server_addresses.begin(); it_serv != m_server_addresses.end(); ++it_serv) {
        if (server_address == it_serv->socket_family_cast(server_address.c_sockaddr()->sa_family)) {
            // Put current address to back of queue
            m_server_addresses.splice(m_server_addresses.end(), m_server_addresses, it_serv);
            break;
        }
    }
}

// This is a workaround for cases when connection is lost (since we don't have migration),
// but waiting for the whole connection idle timer to expire would be too long:
// 1. Start as soon as there are outstanding requests.
// 2. Reset each time we receive a reply.
// 3. Stop when there are no more outstanding requests.
void DoqUpstream::update_req_idle_timer() {
    if (m_requests.empty()) {
        uv_timer_stop(m_req_idle_timer->raw());
        dbglog(m_log, "Short timeout timer stopped");
        return;
    }
    if (uv_is_active((uv_handle_t *) m_req_idle_timer->raw())) {
        tracelog(m_log, "Short timeout timer already running");
        return;
    }
    Millis value = m_config.timeout * 2;
    uv_timer_start(m_req_idle_timer->raw(), short_timeout_timer_cb, value.count(), 0);
    dbglog(m_log, "Short timeout timer set to {}", value);
}

void DoqUpstream::on_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
    RAND_bytes(dest, destlen);
}

} // namespace ag::dns
