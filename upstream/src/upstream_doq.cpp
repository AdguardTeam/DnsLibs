#include "common/time_utils.h"
#include "upstream_doq.h"
#include "upstream.h"
#include <magic_enum.hpp>
#include <cassert>

#ifdef __linux__
#include <time.h>
#endif

#ifdef __MACH__
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

using namespace ag;
using namespace std::chrono;

static constexpr std::string_view DQ_ALPNS[] = {"doq-i02", "doq-i00", "doq", "dq"};
static constexpr int LOCAL_IDLE_TIMEOUT_SEC = 180;

#undef  NEVER
#define NEVER (UINT64_MAX / 2)

#define tracelog_id(l_, pkt_, fmt_, ...) tracelog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)


std::atomic_int64_t dns_over_quic::m_next_request_id{1};


dns_over_quic::buffer::buffer(const uint8_t *data, size_t datalen)
        : buf{data, data + datalen}, tail(datalen)
{}

dns_over_quic::buffer::buffer(size_t datalen) : buf(datalen), tail(0)
{}

bool dns_over_quic::connection_state::is_peer_selected() const {
    return std::holds_alternative<std::unique_ptr<socket_context>>(this->info);
}

std::unique_ptr<dns_over_quic::socket_context> dns_over_quic::connection_state::extract_socket(socket_context *ctx) {
    auto *initial_info = std::get_if<connection_handshake_initial_info>(&this->info);
    if (initial_info == nullptr) {
        return nullptr;
    }

    auto it = std::find_if(initial_info->sockets.begin(), initial_info->sockets.end(),
            [ctx] (const auto &i) { return i.get() == ctx; });
    if (it == initial_info->sockets.end()) {
        return nullptr;
    }

    auto out = std::move(*it);
    initial_info->sockets.erase(it);
    return out;
}

dns_over_quic::dns_over_quic(const upstream_options &opts, const upstream_factory_config &config)
        : upstream(opts, config)
        , m_max_pktlen{NGTCP2_MAX_PKTLEN_IPV6}
        , m_quic_version{NGTCP2_PROTO_VER_V1}
        , m_send_buf(NGTCP2_MAX_PKTLEN_IPV6)
        , m_idle_timer_event(event_new(m_loop->c_base(), -1, EV_TIMEOUT, idle_timer_cb, this))
        , m_handshake_timer_event(event_new(m_loop->c_base(), -1, EV_TIMEOUT, handshake_timer_cb, this))
        , m_retransmit_timer_event(event_new(m_loop->c_base(), -1, EV_TIMEOUT, retransmit_cb, this))
        , m_static_secret{0}
        , m_tls_session_cache(opts.address)
{}

dns_over_quic::~dns_over_quic() {
    submit([this] {
        disconnect("Destructor");
    });

    m_loop->stop(); // Cleanup should still execute since this is event_loopexit
    m_loop->join();
}

#if BORINGSSL_API_VERSION < 10
int dns_over_quic::set_encryption_secrets(SSL *ssl, enum ssl_encryption_level_t ossl_level,
                                          const uint8_t *read_secret,
                                          const uint8_t *write_secret, size_t secret_len) {
    auto doq = static_cast<dns_over_quic *>(SSL_get_app_data(ssl));
    if (doq->on_key(doq->from_ossl_level(ossl_level), read_secret, write_secret, secret_len) != 0) {
        return 0;
    }
    return 1;
}
#else
int dns_over_quic::set_rx_secret(SSL *ssl, enum ssl_encryption_level_t ossl_level,
                                 const SSL_CIPHER *cipher,
                                 const uint8_t *read_secret, size_t secret_len) {
    auto doq = static_cast<dns_over_quic *>(SSL_get_app_data(ssl));
    if (doq->on_key(doq->from_ossl_level(ossl_level), read_secret, nullptr, secret_len) != 0) {
        return 0;
    }
    return 1;
}
int dns_over_quic::set_tx_secret(SSL *ssl, enum ssl_encryption_level_t ossl_level,
                                      const SSL_CIPHER *cipher,
                                      const uint8_t *write_secret, size_t secret_len) {
    auto doq = static_cast<dns_over_quic *>(SSL_get_app_data(ssl));
    if (doq->on_key(doq->from_ossl_level(ossl_level), nullptr, write_secret, secret_len) != 0) {
        return 0;
    }
    return 1;
}
#endif /** else of BORINGSSL_API_VERSION < 10 */

int dns_over_quic::add_handshake_data(SSL *ssl, enum ssl_encryption_level_t ossl_level,
                                      const uint8_t *data, size_t len) {
    auto doq = static_cast<dns_over_quic *>(SSL_get_app_data(ssl));
    doq->write_client_handshake(doq->from_ossl_level(ossl_level), data, len);
    return 1;
}

int dns_over_quic::flush_flight(SSL *ssl) {
    (void)ssl;
    return 1;
}

int dns_over_quic::send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert) {
    (void)ssl;
    (void)level;
    (void)alert;

    auto doq = (dns_over_quic *)SSL_get_app_data(ssl);
    errlog(doq->m_log, "SSL error ({}), sending alert", alert);

    auto res = SSL_alert_from_verify_result(alert);
    if (res == SSL_AD_BAD_CERTIFICATE
            || res == SSL_AD_CERTIFICATE_EXPIRED
            || res == SSL_AD_CERTIFICATE_REVOKED
            || res == SSL_AD_UNSUPPORTED_CERTIFICATE
            || res == SSL_AD_CERTIFICATE_UNKNOWN) {
        std::scoped_lock l(doq->m_global);
        for (auto &cur : doq->m_requests) {
            cur.second.cond.notify_all();
        }
    }

    return 1;
}

static auto quic_method = SSL_QUIC_METHOD{
#if BORINGSSL_API_VERSION < 10
        dns_over_quic::set_encryption_secrets,
#else
        dns_over_quic::set_rx_secret,
        dns_over_quic::set_tx_secret,
#endif
        dns_over_quic::add_handshake_data,
        dns_over_quic::flush_flight,
        dns_over_quic::send_alert,
};

void dns_over_quic::retransmit_cb(evutil_socket_t, short, void *data) {
    auto doq = static_cast<dns_over_quic *>(data);
    tracelog(doq->m_log, "{}(): ...", __func__);
    if (doq->m_state == STOP) {
        return;
    }

    if (int ret = doq->handle_expiry(); ret != 0) {
        doq->disconnect("Handling expiry error");
        return;
    }

    if (int ret = doq->on_write();
            ret != NETWORK_ERR_OK) {
        doq->disconnect(AG_FMT("Retransmission error ({})", ret));
    }
}

void dns_over_quic::idle_timer_cb(evutil_socket_t, short, void *data) {
    auto doq = static_cast<dns_over_quic *>(data);
    doq->disconnect("Idle timer expired");
}

void dns_over_quic::handshake_timer_cb(evutil_socket_t, short, void *data) {
    auto doq = static_cast<dns_over_quic *>(data);
    evtimer_del(doq->m_idle_timer_event.get());
    doq->disconnect("Handshake timer expired");
}

void dns_over_quic::send_requests() {
    m_global.lock();

    for (auto &[id, req] : m_requests) {
        if (req.is_onfly) {
            continue;
        }

        auto idle_expiry = ngtcp2_conn_get_idle_expiry(m_conn);
        milliseconds diff = ceil<milliseconds>(nanoseconds{idle_expiry - req.starting_time});
        if (diff < m_options.timeout * 2) {
            m_global.unlock();
            disconnect(AG_FMT("Too little time to process the request, id: {}", req.request_id));
            reinit();
            return;
        }

        int64_t stream_id = -1;
        if (auto rv = ngtcp2_conn_open_bidi_stream(m_conn, &stream_id, nullptr); rv != 0) {
            warnlog(m_log, "Can't create new stream: {}", ngtcp2_strerror(rv));
            if (NGTCP2_ERR_STREAM_ID_BLOCKED == rv) {
                break;
            }
        }

        if (stream_id == -1) {
            m_global.unlock();
            disconnect("Stream ID is wrong");
            return;
        }

        stream &stream = m_streams[stream_id];
        stream.stream_id = stream_id;
        stream.request_id = req.request_id;
        stream.send_info.buf.reset(evbuffer_new());
        evbuffer_add(stream.send_info.buf.get(), ldns_buffer_current(req.request_buffer.get()),
                     ldns_buffer_remaining(req.request_buffer.get()));

        m_stream_send_queue.push_back(stream_id);

        tracelog(m_log, "Sending request, id: {}", req.request_id);
        if (int ret = on_write();
                ret != NETWORK_ERR_OK) {
            m_global.unlock();
            if (ret == NETWORK_ERR_SEND_BLOCKED) {
                req.is_onfly = true;
            } else {
                disconnect(AG_FMT("Sending request error: {}, id: {}", ret, id));
            }
            return;
        }

        req.is_onfly = true;
    }

    m_global.unlock();

    update_idle_timer(false);
}

ErrString dns_over_quic::init() {
    std::string_view url = m_options.address;

    assert(ag::utils::starts_with(url, SCHEME));
    url.remove_prefix(SCHEME.size());
    url = url.substr(0, url.find('/'));

    auto[host, port] = ag::utils::split_host_port(url);
    m_server_name = ag::utils::trim(host);
    if (m_server_name.empty()) {
        return "Server name is empty";
    }

    if (port.empty()) {
        m_port = DEFAULT_PORT;
    } else if (auto port_int = ag::utils::to_integer<uint16_t>(port); !port_int.has_value()) {
        return "Invalid port number";
    } else {
        m_port = port_int.value();
    }

    ag::bootstrapper::params bootstrapper_params = {
            .address_string = m_server_name,
            .default_port = m_port,
            .bootstrap = m_options.bootstrap,
            .timeout = m_options.timeout,
            .upstream_config = m_config,
            .outbound_interface = m_options.outbound_interface,
    };
    m_bootstrapper = std::make_unique<bootstrapper>(bootstrapper_params);
    if (auto check = m_bootstrapper->init(); check.has_value()) {
        return "Bootstrapper init failed";
    }

    m_callbacks = ngtcp2_callbacks{
            ngtcp2_crypto_client_initial_cb,
            nullptr, // recv_client_initial
            recv_crypto_data,
            nullptr, // handshake_completed,
            version_negotiation, // recv_version_negotiation
            ngtcp2_crypto_encrypt_cb,
            ngtcp2_crypto_decrypt_cb,
            ngtcp2_crypto_hp_mask,
            recv_stream_data,
            nullptr, // acked_crypto_offset,
            acked_stream_data_offset, // acked_stream_data_offset,
            nullptr, // stream_open
            on_close_stream,
            nullptr, // recv_stateless_reset
            ngtcp2_crypto_recv_retry_cb,
            nullptr, // extend_max_streams_bidi,
            nullptr, // extend_max_streams_uni
            nullptr, // rand,
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
    };

    m_remote_addr_empty = ag::SocketAddress("::", m_port);

    if (int ret = init_ssl_ctx(); ret != 0) {
        return "Creation SSL context failed";
    }

    return std::nullopt;
}

dns_over_quic::exchange_result dns_over_quic::exchange(ldns_pkt *request, const dns_message_info *) {
    if (std::scoped_lock l(m_global); m_server_addresses.empty()) {
        bootstrapper::resolve_result bootstrapper_res = m_bootstrapper->get();
        if (bootstrapper_res.error.has_value()) {
            warnlog(m_log, "Bootstrapper hasn't results");
            return {nullptr, "Failed to resolve address of server"};
        }

        m_server_addresses.assign(bootstrapper_res.addresses.begin(), bootstrapper_res.addresses.end());
    }

    ldns_buffer *buffer = ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY);
    ldns_status status = ldns_pkt2buffer_wire(buffer, request);
    if (status != LDNS_STATUS_OK) {
        assert(0);
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }
    ldns_buffer_flip(buffer);

    int64_t request_id = m_next_request_id++;
    {
        std::scoped_lock l(m_global);
        request_t &req = m_requests[request_id];
        req.starting_time = get_tstamp();
        req.request_id = request_id;
        req.request_buffer.reset(buffer);
    }
    tracelog_id(m_log, request, "Creation new request, id: {}, connection state: {}",
            request_id, magic_enum::enum_name(m_state.load()));

    submit([this]{
        if (m_state != RUN) {
            int res = this->reinit();
            if (res != NETWORK_ERR_HANDSHAKE_RUN && res != NETWORK_ERR_OK) {
                disconnect(AG_FMT("Reinit failed ({})", res));
            }
        } else {
            this->send_requests();
        }
    });

    std::unique_lock l(m_global);
    request_t &req = m_requests[request_id];
    auto timeout = req.cond.wait_for(l, m_options.timeout);

    ldns_pkt *res = req.reply_pkt.release();
    assert(m_requests.count(request_id));
    tracelog_id(m_log, request, "Erase request, id: {}, connection state: {}",
            request_id, magic_enum::enum_name(m_state.load()));
    m_requests.erase(request_id);

    if (timeout == std::cv_status::timeout) {
        return {nullptr, TIMEOUT_STR.data()};
    }

    if (res != nullptr) {
        return {ldns_pkt_ptr(res), std::nullopt};
    }

    return {nullptr, "Request failed (empty packet)"};
}

void dns_over_quic::on_socket_connected(void *arg) {
    auto *ctx = (socket_context *)arg;
    dns_over_quic *self = ctx->upstream;

    const SocketAddress &peer = ctx->socket->get_peer();
    tracelog(self->m_log, "{}(): {}", __func__, peer.str());

    auto *info = std::get_if<connection_handshake_initial_info>(&self->m_conn_state.info);
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

void dns_over_quic::on_socket_read(void *arg, Uint8View data) {
    auto *ctx = (socket_context *)arg;
    dns_over_quic *self = ctx->upstream;
    tracelog(self->m_log, "{}(): Read {} bytes from {}", __func__, data.size(), ctx->socket->get_peer().str());

    std::string disconnect_reason;
    if (int ret = self->feed_data(data); ret != NETWORK_ERR_OK) {
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

    self->update_idle_timer(false);

    return;

    fail:
    // if the peer is not yet selected and we have some pending endpoints,
    // do not disconnect immediately - wait for other ones
    if (const connection_handshake_initial_info *info;
            self->m_conn_state.is_peer_selected()
            || nullptr == (info = std::get_if<connection_handshake_initial_info>(&self->m_conn_state.info))
            || info->sockets.empty()) {
        self->disconnect(disconnect_reason);
    }
}

void dns_over_quic::on_socket_close(void *arg, std::optional<socket::error> error) {
    auto *ctx = (socket_context *) arg;
    dns_over_quic *self = ctx->upstream;

    const SocketAddress &peer = ctx->socket->get_peer();
    if (error.has_value()) {
        dbglog(self->m_log, "Failed to connect to {}: {} ({})", peer.str(), error->description, error->code);
        if (!self->m_conn_state.is_peer_selected()) {
            self->disqualify_server_address(peer);
        }
    } else {
        dbglog(self->m_log, "Connection to {} closed", peer.str());
    }

    auto drop = self->m_conn_state.extract_socket(ctx);
    // if the peer is not yet selected and we have some pending endpoints,
    // do not disconnect immediately - wait for other ones
    if (const connection_handshake_initial_info *info;
            self->m_conn_state.is_peer_selected()
            || nullptr == (info = std::get_if<connection_handshake_initial_info>(&self->m_conn_state.info))
            || info->sockets.empty()) {
        self->disconnect("Connection is closed");
    }
}

int dns_over_quic::on_write() {
    if (m_send_buf.size() > 0) {
        if (auto rv = send_packet(); rv != NETWORK_ERR_OK) {
            if (rv != NETWORK_ERR_SEND_BLOCKED) {
                disconnect("Resending packet failed");
            }
            return rv;
        }
    }

    assert(m_send_buf.left() >= m_max_pktlen);

    if (auto rv = write_streams(); rv != NETWORK_ERR_OK) {
        if (rv == NETWORK_ERR_SEND_BLOCKED) {
            schedule_retransmit();
        }
        return rv;
    }

    schedule_retransmit();
    return 0;
}

int dns_over_quic::write_streams() {
    ngtcp2_vec vec[2];

    for (;;) {
        int64_t stream_id = -1;
        size_t vcnt = 0;
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

        while (!m_stream_send_queue.empty() && ngtcp2_conn_get_max_data_left(m_conn)) {
            stream_id = m_stream_send_queue.front();
            auto it = m_streams.find(stream_id);
            if (it == m_streams.end()) {
                m_stream_send_queue.pop_front();
                continue;
            }
            stream &st = it->second;
            evbuffer *buf = st.send_info.buf.get();
            if (evbuffer_get_length(buf) - st.send_info.read_position == 0) {
                m_stream_send_queue.pop_front();
                continue;
            }
            evbuffer_ptr position = {};
            evbuffer_ptr_set(buf, &position, st.send_info.read_position, EVBUFFER_PTR_SET);
            vcnt = evbuffer_peek(buf, evbuffer_get_length(buf), &position, (evbuffer_iovec *)vec, std::size(vec));
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
            break;
        }

        ngtcp2_ssize ndatalen;
        ngtcp2_pkt_info pi;

        auto initial_ts = get_tstamp();
        tracelog(m_log, "{}(): data={}, wpos={}, buf_size={}, size={}, left={}, max_pktlen={}",
                __func__, (void *)m_send_buf.buf.data(), (void *)m_send_buf.wpos(),
                m_send_buf.buf.size(), m_send_buf.size(), m_send_buf.left(), m_max_pktlen);
        auto nwrite = ngtcp2_conn_writev_stream(
                m_conn, nullptr, &pi, m_send_buf.wpos(), m_max_pktlen, &ndatalen, flags,
                stream_id, vec, vcnt, initial_ts);

        if (nwrite < 0) {
            switch (nwrite) {
            case NGTCP2_ERR_STREAM_DATA_BLOCKED:
            case NGTCP2_ERR_STREAM_SHUT_WR:
                assert(ndatalen == -1);
                warnlog(m_log, "Can't write stream {} because: {}", stream_id, ngtcp2_strerror(nwrite));
                m_stream_send_queue.pop_front();
                continue;
            case NGTCP2_ERR_WRITE_MORE:
                assert(ndatalen > 0);
                m_streams[stream_id].send_info.read_position += ndatalen;
                m_stream_send_queue.pop_front();
                continue;
            }
            errlog(m_log, "ngtcp2_conn_write_stream: {}", ngtcp2_strerror(nwrite));
            return NETWORK_ERR_FATAL;
        }

        if (nwrite == 0) {
            return 0;
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

int dns_over_quic::send_packet(socket *active_socket, Uint8View data) {
    tracelog(m_log, "Sending {} bytes to {}", data.size(), active_socket->get_peer().str());
    auto e = active_socket->send(data);
    if (e.has_value()) {
        if (ag::utils::socket_error_is_eagain(e->code)) {
            return NETWORK_ERR_SEND_BLOCKED;
        } else {
            dbglog(m_log, "Failed to send packet: {} ({})", e->description, e->code);
        }
    }

    m_send_buf.reset();

    return !e.has_value() ? NETWORK_ERR_OK : NETWORK_ERR_DROP_CONN;
}

int dns_over_quic::send_packet() {
    Uint8View data = { m_send_buf.rpos(), m_send_buf.size() };
    if (auto *info = std::get_if<connection_handshake_initial_info>(&m_conn_state.info);
            info != nullptr && info->last_connected_socket != nullptr) {
        return send_packet(info->last_connected_socket->socket.get(), data);
    } else if (auto *active_socket = std::get_if<std::unique_ptr<socket_context>>(&m_conn_state.info)) {
        return send_packet((*active_socket)->socket.get(), data);
    } else {
        errlog(m_log, "{}(): no socket to send data on", __func__);
        assert(0);
        return NETWORK_ERR_DROP_CONN;
    }
}

int dns_over_quic::connect_to_peers(const std::vector<ag::SocketAddress> &current_addresses) {
    std::vector<std::unique_ptr<socket_context>> sockets;
    sockets.reserve(current_addresses.size());

    for (auto &address : current_addresses) {
        auto &ctx = sockets.emplace_back(new socket_context{});
        ctx->upstream = this;
        ctx->socket = this->make_socket(utils::TP_UDP);
        if (auto e = ctx->socket->connect({ m_loop.get(), address,
                    { on_socket_connected, on_socket_read, on_socket_close, ctx.get() } });
                e.has_value()) {
            dbglog(m_log, "Failed to start connection to {}: {} ({})", address.str(), e->description, e->code);
            disqualify_server_address(address);
            sockets.erase(std::next(sockets.end(), -1));
        }
    }

    if (current_addresses.empty()) {
        dbglog(m_log, "None of the current peers are available");
        return NETWORK_ERR_DROP_CONN;
    }

    m_conn_state.info = connection_handshake_initial_info{ std::move(sockets) };

    struct timeval tv{};
    evtimer_pending(m_handshake_timer_event.get(), &tv);
    if (!evutil_timerisset(&tv)) {
        tv = duration_to_timeval(m_options.timeout);
        evtimer_add(m_handshake_timer_event.get(), &tv);
    }
    return NETWORK_ERR_OK;
}

int dns_over_quic::init_quic_conn(const socket *connected_socket) {
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

    ngtcp2_path path = {
            {(size_t)m_local_addr.c_socklen(), (sockaddr *)m_local_addr.c_sockaddr()},
            {(size_t)m_remote_addr_empty.c_socklen(), (sockaddr *)m_remote_addr_empty.c_sockaddr()}};

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);

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

    auto rv = ngtcp2_conn_client_new(&m_conn, &dcid, &scid, &path,
            m_quic_version, &m_callbacks, &settings, &txparams, nullptr, this);
    if (rv != 0) {
        errlog(m_log, "Failed to create ngtcp2_conn: {}", ngtcp2_strerror(rv));
        return -1;
    }

    if (init_ssl() != 0) {
        errlog(m_log, "Failed to create SSL");
        return -1;
    }
    ngtcp2_conn_set_tls_native_handle(m_conn, m_ssl.get());

    update_idle_timer(true);
    return NETWORK_ERR_OK;
}

int dns_over_quic::init_ssl_ctx() {
    m_ssl_ctx.reset(SSL_CTX_new(TLS_client_method()));
    if (m_ssl_ctx == nullptr) {
        return 1;
    }
    SSL_CTX_set_min_proto_version(m_ssl_ctx.get(), TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(m_ssl_ctx.get(), TLS1_3_VERSION);
    SSL_CTX_set_quic_method(m_ssl_ctx.get(), &quic_method);
    // setup our verifier
    SSL_CTX_set_verify(m_ssl_ctx.get(), SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_cert_verify_callback(m_ssl_ctx.get(), dns_over_quic::ssl_verify_callback, nullptr);
    tls_session_cache::prepare_ssl_ctx(m_ssl_ctx.get());
    return 0;
}

int dns_over_quic::init_ssl() {
    m_ssl.reset(SSL_new(m_ssl_ctx.get()));
    if (m_ssl == nullptr) {
        return 1;
    }
    SSL_set_app_data(m_ssl.get(), this);
    SSL_set_tlsext_host_name(m_ssl.get(), m_server_name.c_str());
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
    SSL_set_alpn_protos(m_ssl.get(), (uint8_t *)alpn.data(), alpn.size());

    m_tls_session_cache.prepare_ssl(m_ssl.get());

    if (ssl_session_ptr session = m_tls_session_cache.get_session()) {
        dbglog(m_log, "Using a cached TLS session");
        SSL_set_session(m_ssl.get(), session.get()); // UpRefs the session
    } else {
        dbglog(m_log, "No cached TLS sessions available");
    }

    return 0;
}

void dns_over_quic::write_client_handshake(ngtcp2_crypto_level level, const uint8_t *data, size_t datalen) {
    auto &crypto = m_crypto[level];
    crypto.data.emplace_back(data, datalen);
    auto &buf = crypto.data.back();
    ngtcp2_conn_submit_crypto_data(m_conn, level, buf.rpos(), buf.size());
}

int dns_over_quic::feed_data(Uint8View data) {
    auto path = ngtcp2_path{ {(size_t)m_local_addr.c_socklen(), (sockaddr *)m_local_addr.c_sockaddr()},
                             {(size_t)m_remote_addr_empty.c_socklen(), (sockaddr *)m_remote_addr_empty.c_sockaddr()} };

    auto initial_ts = get_tstamp();

    ngtcp2_pkt_info pi{};
    auto rv = ngtcp2_conn_read_pkt(m_conn, &path, &pi, data.data(), data.size(), initial_ts);

    if (rv != 0 && rv != NGTCP2_ERR_RECV_VERSION_NEGOTIATION) {
        dbglog(m_log, "ngtcp2_conn_read_pkt: {}", ngtcp2_strerror(rv));
    }

    return rv;
}

int dns_over_quic::version_negotiation(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                                       const uint32_t *sv, size_t nsv, void *user_data) {
    auto doq = static_cast<dns_over_quic *>(user_data);
    uint32_t version = 0;
    bool selected = false;
    for (size_t i = 0; i < nsv; i++) {
        if (sv[i] == NGTCP2_PROTO_VER_V1
                || (sv[i] >= NGTCP2_PROTO_VER_DRAFT_MIN && sv[i] <= NGTCP2_PROTO_VER_DRAFT_MAX)) {
            selected = true;
            version = std::max(version, sv[i]);
        }
    }
    if (doq->m_log.is_enabled(ag::LogLevel::LOG_LEVEL_DEBUG)) {
        std::string list;
        for (size_t i = 0; i < nsv; i++) {
            list += (i ? ", " : "") + AG_FMT("{:#x}", sv[i]);
        }
        dbglog(doq->m_log, "Version negotiation. Client supported versions: {:#x}, drafts {:#x} to {:#x}, server supported versions: {}",
               NGTCP2_PROTO_VER_V1, NGTCP2_PROTO_VER_DRAFT_MIN, NGTCP2_PROTO_VER_DRAFT_MAX, list);
    }

    if (selected) {
        dbglog(doq->m_log, "Switching from QUIC version {:#x} to negotiated QUIC version {:#x}", doq->m_quic_version, version);
        doq->m_quic_version = version;
        return 0;
    }

    dbglog(doq->m_log, "QUIC version can't be negotiated - no common supported QUIC versions with server.");
    return -1;
}

int dns_over_quic::recv_crypto_data(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                                    uint64_t offset, const uint8_t *data, size_t datalen,
                                    void *user_data) {
    (void)offset;
    (void)user_data;
    if (ngtcp2_crypto_read_write_crypto_data(conn, crypto_level, data, datalen) != 0) {
        if (auto err = ngtcp2_conn_get_tls_error(conn); err) {
            return err;
        }
        return NGTCP2_ERR_CRYPTO;
    }

    return 0;
}

int dns_over_quic::on_key(ngtcp2_crypto_level level, const uint8_t *rx_secret,
                          const uint8_t *tx_secret, size_t secretlen) {
    std::array<uint8_t, 64> rx_key{}, rx_iv{}, rx_hp_key{}, tx_key{}, tx_iv{}, tx_hp_key{};

    std::string direction;
    if (rx_secret) {
        direction += "RX";
        if (ngtcp2_crypto_derive_and_install_rx_key(
                m_conn, rx_key.data(), rx_iv.data(), rx_hp_key.data(), level,
                rx_secret, secretlen) != 0) {
            return -1;
        }
    }

    if (tx_secret) {
        direction += "TX";
        if (ngtcp2_crypto_derive_and_install_tx_key(
                m_conn, tx_key.data(), tx_iv.data(), tx_hp_key.data(), level,
                tx_secret, secretlen) != 0) {
            return -1;
        }
    }

    switch (level) {
    case NGTCP2_CRYPTO_LEVEL_EARLY:
        dbglog(m_log, "Crypto {} level: EARLY", direction);
        break;
    case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
        dbglog(m_log, "Crypto {} level: HANDSHAKE", direction);
        break;
    case NGTCP2_CRYPTO_LEVEL_APPLICATION:
        dbglog(m_log, "Crypto {} level: APP", direction);
        break;
    default:
        dbglog(m_log, "Crypto {} level: UNKNOWN", direction);
        assert(0);
    }

    return 0;
}

int dns_over_quic::update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
                              ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                              ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                              const uint8_t *current_rx_secret,
                              const uint8_t *current_tx_secret, size_t secretlen,
                              void *user_data) {
    (void)user_data;

    std::array<uint8_t, 64> rx_key{}, tx_key{};

    if (ngtcp2_crypto_update_key(conn, rx_secret, tx_secret, rx_aead_ctx,
                                 rx_key.data(), rx_iv, tx_aead_ctx, tx_key.data(),
                                 tx_iv, current_rx_secret, current_tx_secret,
                                 secretlen) != 0) {
        return -1;
    }

    return 0;
}

// NOTE: Use a monotonic clock that is not user-adjustable and doesn't stop when system goes to sleep
ngtcp2_tstamp dns_over_quic::get_tstamp() {
#ifdef __linux__
    static constexpr int64_t NANOS_PER_SEC = 1'000'000'000;
    timespec ts{};
    if (clock_gettime(CLOCK_BOOTTIME, &ts) != -1) {
        return (ts.tv_sec * NANOS_PER_SEC) + ts.tv_nsec;
    }
#endif
    return std::chrono::duration_cast<std::chrono::nanoseconds>
           (std::chrono::steady_clock::now().time_since_epoch()).count();
}

int dns_over_quic::recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                                    uint64_t offset, const uint8_t *data, size_t datalen,
                                    void *user_data, void *stream_user_data) {
    (void)conn;
    (void)flags;
    (void)offset;
    (void)stream_user_data;

    auto doq = static_cast<dns_over_quic *>(user_data);

    doq->update_idle_timer(true);

    auto st = doq->m_streams.find(stream_id);
    if (st == doq->m_streams.end()) {
        warnlog(doq->m_log, "Stream died");
        return 0;
    }

    if (st->second.raw_data.empty() && (flags & NGTCP2_STREAM_DATA_FLAG_FIN)) {
        doq->process_reply(st->second.request_id, data, datalen);
    } else {
        auto &raw_vec = st->second.raw_data;
        raw_vec.reserve(raw_vec.size() + datalen);
        std::copy(data, data + datalen, std::back_inserter(raw_vec));

        if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
            doq->process_reply(st->second.request_id, raw_vec.data(), raw_vec.size());
        }
    }

    return 0;
}

int dns_over_quic::get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                         uint8_t *token, size_t cidlen, void *user_data) {
    (void)conn;

    auto doq = (dns_over_quic *)user_data;

    RAND_bytes(cid->data, cidlen);
    cid->datalen = cidlen;
    auto md = ngtcp2_crypto_md{const_cast<EVP_MD *>(EVP_sha256())};
    if (ngtcp2_crypto_generate_stateless_reset_token(
            token, &md, doq->m_static_secret.data(), doq->m_static_secret.size(), cid) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

int dns_over_quic::handshake_confirmed(ngtcp2_conn *conn, void *data) {
    (void)conn;

    auto doq = (dns_over_quic *)data;
    tracelog(doq->m_log, "{}", __func__);
    evtimer_del(doq->m_handshake_timer_event.get());

    const uint8_t *buf = nullptr;
    uint32_t len = 0;
    SSL_get0_alpn_selected(doq->m_ssl.get(), &buf, &len);
    dbglog(doq->m_log, "Selected ALPN: {}", std::string_view{(char *)buf, len});

    doq->m_state = RUN;
    doq->update_idle_timer(true);
    doq->send_requests();
    return 0;
}

void dns_over_quic::ag_ngtcp2_settings_default(ngtcp2_settings &settings, ngtcp2_transport_params &params) const {
    settings.max_udp_payload_size = m_max_pktlen;
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

int dns_over_quic::reinit() {
    if (m_state == HANDSHAKE || m_state == RUN) {
        return NETWORK_ERR_HANDSHAKE_RUN;
    }
    m_state = HANDSHAKE;

    m_streams.clear();
    m_stream_send_queue.clear();

    std::vector<ag::SocketAddress> current_addresses;

    {
        std::scoped_lock l(m_global);
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

int dns_over_quic::on_close_stream(ngtcp2_conn *conn, int64_t stream_id,
                                   uint64_t app_error_code, void *user_data,
                                   void *stream_user_data) {
    (void)conn;
    (void)app_error_code;
    (void)stream_user_data;

    auto doq = static_cast<dns_over_quic *>(user_data);

    doq->m_streams.erase(stream_id);
    return 0;
}

int dns_over_quic::acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                            uint64_t offset, uint64_t datalen, void *user_data,
                                            void *stream_user_data) {
    (void)conn;
    (void)offset;
    (void)stream_user_data;

    auto doq = (dns_over_quic *)user_data;
    if (auto it = doq->m_streams.find(stream_id); it != doq->m_streams.end()) {
        auto &stream = it->second;
        evbuffer *buf = stream.send_info.buf.get();
        evbuffer_drain(buf, datalen);
        stream.send_info.read_position -= datalen;
        assert(stream.send_info.read_position >= 0);
    }

    return 0;
}

void dns_over_quic::submit(std::function<void()> &&f) const {
    m_loop->submit(std::move(f));
}

void dns_over_quic::process_reply(int64_t request_id, const uint8_t *request_data, size_t request_data_len) {
    std::scoped_lock lg(m_global);
    auto req_it = m_requests.find(request_id);
    if (req_it != m_requests.end()) {
        ldns_pkt *pkt = nullptr;
        int r = ldns_wire2pkt(&pkt, request_data, request_data_len);
        if (r != LDNS_STATUS_OK) {
            pkt = nullptr;
        }
        req_it->second.reply_pkt.reset(pkt);
        req_it->second.cond.notify_all();
    }
}

void dns_over_quic::disconnect(std::string_view reason) {
    m_state = STOP;

    dbglog(m_log, "Disconnect reason: {}", reason);
    ngtcp2_conn_del(std::exchange(m_conn, nullptr));
    m_read_event.reset();
    evtimer_del(m_handshake_timer_event.get());
    evtimer_del(m_idle_timer_event.get());
    evtimer_del(m_retransmit_timer_event.get());

    m_conn_state.info.emplace<std::monostate>();

    m_ssl.reset();

    std::scoped_lock l(m_global);
    for (auto &cur : m_requests) {
        if (cur.second.is_onfly) {
            tracelog(m_log, "Call condvar for request, id: {}", cur.first);
            cur.second.cond.notify_all();
        }
    }
}

int dns_over_quic::handle_expiry() {
    auto now = get_tstamp();
    if (auto rv = ngtcp2_conn_handle_expiry(m_conn, now); rv != 0) {
        errlog(m_log, "Handling expiry error: {}", ngtcp2_strerror(rv));
        return -1;
    }

    return 0;
}

void dns_over_quic::schedule_retransmit() {
    auto expiry_ns = ngtcp2_conn_get_expiry(m_conn);
    if (expiry_ns > NEVER) {
        return;
    }
    auto now_ns = get_tstamp();

    struct timeval tv{0};
    if (expiry_ns > now_ns) {
        nanoseconds timeout_ns{expiry_ns - now_ns};
        tv = duration_to_timeval(ceil<microseconds>(timeout_ns));
    }
    evtimer_del(m_retransmit_timer_event.get());
    tracelog(m_log, "Next retransmit in {}", microseconds(1000000 * tv.tv_sec + tv.tv_usec));
    evtimer_add(m_retransmit_timer_event.get(), &tv);
}

int dns_over_quic::ssl_verify_callback(X509_STORE_CTX *ctx, void *arg) {
    (void)arg;

    SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    auto doq = (dns_over_quic *)SSL_get_app_data(ssl);

    const certificate_verifier *verifier = doq->m_config.socket_factory->get_certificate_verifier();
    if (verifier == nullptr) {
        dbglog(doq->m_log, "Cannot verify certificate due to verifier is not set");
        return 0;
    }

    if (auto err = verifier->verify(ctx, SSL_get_servername(ssl, SSL_get_servername_type(ssl)));
            err.has_value()) {
        dbglog(doq->m_log, "Failed to verify certificate: {}", err.value());
        return 0;
    }

    tracelog(doq->m_log, "Verified successfully");

    return 1;
}

void dns_over_quic::disqualify_server_address(const SocketAddress &server_address) {
    std::scoped_lock l(m_global);
    for (auto it_serv = m_server_addresses.begin(); it_serv != m_server_addresses.end(); ++it_serv) {
        if (server_address == it_serv->socket_family_cast(server_address.c_sockaddr()->sa_family)) {
            // Put current address to back of queue
            m_server_addresses.splice(m_server_addresses.end(), m_server_addresses, it_serv);
            break;
        }
    }
}

ngtcp2_crypto_level dns_over_quic::from_ossl_level(enum ssl_encryption_level_t ossl_level) const {
    switch (ossl_level) {
        case ssl_encryption_initial:
            return NGTCP2_CRYPTO_LEVEL_INITIAL;
        case ssl_encryption_early_data:
            return NGTCP2_CRYPTO_LEVEL_EARLY;
        case ssl_encryption_handshake:
            return NGTCP2_CRYPTO_LEVEL_HANDSHAKE;
        case ssl_encryption_application:
            return NGTCP2_CRYPTO_LEVEL_APPLICATION;
        default:
            warnlog(m_log, "Unknown encryption level");
            assert(0);
    }
}

static microseconds get_event_remaining_timeout(event *ev) {
    timeval next{}, now{};
    evtimer_pending(ev, &next);
    event_base_gettimeofday_cached(event_get_base(ev), &now);
    if (evutil_timercmp(&next, &now, >)) {
        evutil_timersub(&next, &now, &next);
        return microseconds{next.tv_sec * 1000000LL + next.tv_usec};
    }
    return microseconds{0};
}

void dns_over_quic::update_idle_timer(bool reset) {
    bool has_inflight_requests = false;
    {
        std::scoped_lock l(m_global);
        has_inflight_requests = !m_requests.empty();
    }

    milliseconds value{0};
    if (!has_inflight_requests) {
        auto effective_idle_timeout = int64_t(ngtcp2_conn_get_idle_expiry(m_conn)) - get_tstamp();
        if (effective_idle_timeout > 0) {
            value = ceil<milliseconds>(nanoseconds{effective_idle_timeout});
            dbglog(m_log, "Idle timer reset with long timeout, {} left", value);
        }
    } else {
        value = m_options.timeout * 2;
        if (!reset) {
            milliseconds pending = ceil<milliseconds>(get_event_remaining_timeout(m_idle_timer_event.get()));
            if (pending <= value) {
                dbglog(m_log, "Idle timer unchanged, {} left", pending);
                return;
            } else {
                dbglog(m_log, "Idle timer reduced from {} to short timeout, {} left", pending, value);
            }
        } else {
            dbglog(m_log, "Idle timer reset with short timeout, {} left", value);
        }
    }

    timeval tv = duration_to_timeval(value);
    evtimer_add(m_idle_timer_event.get(), &tv);
}
