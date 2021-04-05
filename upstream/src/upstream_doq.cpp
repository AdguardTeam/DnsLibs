#include "upstream_doq.h"
#include "upstream.h"

#ifdef __MACH__
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

using namespace ag;
using namespace std::chrono;

static constexpr uint8_t DQ_ALPN_I00[] = {0x07, 'd', 'o', 'q', '-', 'i', '0', '0'};
static constexpr uint8_t DQ_ALPN_I02[] = {0x07, 'd', 'o', 'q', '-', 'i', '0', '2'};
static constexpr int LOCAL_IDLE_TIMEOUT_SEC = 180;

#undef  NEVER
#define NEVER (UINT64_MAX / 2)

#define tracelog_id(l_, pkt_, fmt_, ...) tracelog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)


std::atomic_int64_t dns_over_quic::m_next_request_id{1};


dns_over_quic::buffer::buffer(const uint8_t *data, size_t datalen)
        : buf{data, data + datalen}, tail(buf.data() + datalen)
{}

dns_over_quic::buffer::buffer(size_t datalen) : buf(datalen), tail(buf.data())
{}

dns_over_quic::dns_over_quic(const upstream_options &opts, const upstream_factory_config &config)
        : upstream(opts, config)
        , m_max_pktlen{NGTCP2_MAX_PKTLEN_IPV6}
        , m_send_buf(NGTCP2_MAX_PKTLEN_IPV6)
        , m_static_secret{0}
        , m_tls_session_cache(opts.address)
{}

dns_over_quic::~dns_over_quic() {
    submit([this] {
        disconnect("Destructor");
    });

    m_loop->stop(); // Cleanup should still execute since this is event_loopexit
    m_loop->join();

    if (m_idle_timer_event) {
        event_free(std::exchange(m_idle_timer_event, nullptr));
    }

    if (m_handshake_timer_event) {
        event_free(std::exchange(m_handshake_timer_event, nullptr));
    }

    if (m_retransmit_timer_event) {
        event_free(std::exchange(m_retransmit_timer_event, nullptr));
    }

    if (m_ssl_ctx) {
        SSL_CTX_free(std::exchange(m_ssl_ctx, nullptr));
    }
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
        std::lock_guard lg(doq->m_global);
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
    if (doq->m_state == STOP) {
        return;
    }

    if (int ret = doq->handle_expiry(); ret != 0) {
        doq->disconnect("Handling expiry error");
    }

    if (int ret = doq->on_write(); ret != 0) {
        doq->disconnect(AG_FMT("Retransmission error ({})", ret));
    }
}

void dns_over_quic::idle_timer_cb(evutil_socket_t, short, void *data) {
    auto doq = static_cast<dns_over_quic *>(data);
    doq->disconnect("Idle timer expired");
}

void dns_over_quic::handshake_timer_cb(evutil_socket_t, short, void *data) {
    auto doq = static_cast<dns_over_quic *>(data);
    evtimer_del(doq->m_idle_timer_event);
    doq->disconnect("Handshake timer expired");
}

void dns_over_quic::read_cb(evutil_socket_t, short, void *data) {
    auto doq = static_cast<dns_over_quic *>(data);
    if (int ret = doq->on_read(); ret != NETWORK_ERR_OK) {
        doq->disconnect(AG_FMT("Reading error ({})", ret));
        return;
    }
    if (int ret = doq->on_write(); ret != NETWORK_ERR_OK) {
        warnlog(doq->m_log, "An error happened while writing: {} line: {}", ret, __LINE__);
        doq->disconnect(AG_FMT("Writing error ({})", ret));
    }
}

void dns_over_quic::send_requests() {
    m_global.lock();

    for (auto &req : m_requests) {
        if (req.second.is_onfly) {
            continue;
        }

        auto idle_expiry = ngtcp2_conn_get_idle_expiry(m_conn);
        milliseconds diff = ceil<milliseconds>(nanoseconds{idle_expiry - req.second.starting_time});
        if (diff < m_options.timeout * 2) {
            m_global.unlock();
            disconnect(AG_FMT("Too little time to process the request, id: {}", req.second.request_id));
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
        stream.request_id = req.second.request_id;
        stream.send_info.buf.reset(evbuffer_new());
        evbuffer_add(stream.send_info.buf.get(), ldns_buffer_current(req.second.request_buffer.get()),
                     ldns_buffer_remaining(req.second.request_buffer.get()));

        m_stream_send_queue.push_back(stream_id);

        tracelog(m_log, "Sending request, id: {}", req.second.request_id);
        if (int ret = on_write(); ret != NETWORK_ERR_OK) {
            m_global.unlock();
            if (ret == NETWORK_ERR_SEND_BLOCKED) {
                req.second.is_onfly = true;
            } else {
                disconnect(AG_FMT("Sending request error: {}, id: {}", ret, req.first));
            }
            return;
        }

        req.second.is_onfly = true;
    }

    m_global.unlock();

    update_idle_timer(false);
}

evutil_socket_t dns_over_quic::create_ipv4_socket() {
    evutil_socket_t fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        warnlog(m_log, "Error creating IPv4 socket: {}", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        return -1;
    }
    return fd;
}


evutil_socket_t dns_over_quic::create_dual_stack_socket() {
    evutil_socket_t fd;

    fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        warnlog(m_log, "Error creating IPv6 socket: {}", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        return -1;
    }

    unsigned int disable = 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&disable, sizeof(disable)) == -1) {
        warnlog(m_log, "Error making socket dual-stack: {}", evutil_socket_error_to_string(evutil_socket_geterror(fd)));
        evutil_closesocket(fd);
        return -1;
    }

    return fd;
}

err_string dns_over_quic::init() {
    std::string_view url = m_options.address;

    assert(ag::utils::starts_with(url, SCHEME));
    url.remove_prefix(SCHEME.size());
    if (url.back() == '/') {
        url.remove_suffix(1);
    }

    auto split_res = ag::utils::split_host_port(url);
    m_server_name = split_res.first.empty() ? "" : std::string(split_res.first);
    m_port = split_res.second.empty() ? DEFAULT_PORT : atoi(std::string(split_res.second.data()).c_str());

    ag::bootstrapper::params bootstrapper_params = {
            .address_string = split_res.first,
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

    m_callbacks = ngtcp2_conn_callbacks{
            ngtcp2_crypto_client_initial_cb,
            nullptr, // recv_client_initial
            recv_crypto_data,
            nullptr, // handshake_completed,
            nullptr, // recv_version_negotiation
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

    m_remote_addr_empty = ag::socket_address("::", m_port);

    m_idle_timer_event = event_new(m_loop->c_base(), -1, EV_TIMEOUT, idle_timer_cb, this);
    m_handshake_timer_event = event_new(m_loop->c_base(), -1, EV_TIMEOUT, handshake_timer_cb, this);
    m_retransmit_timer_event = event_new(m_loop->c_base(), -1, EV_TIMEOUT, retransmit_cb, this);

    if (int ret = init_ssl_ctx(); ret != 0) {
        return "Creation SSL context failed";
    }

    return std::nullopt;
}

dns_over_quic::exchange_result dns_over_quic::exchange(ldns_pkt *request) {
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
    tracelog_id(m_log, request, "Creation new request, id: {}, connection state: {}", request_id, m_state);

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
    tracelog_id(m_log, request, "Erase request, id: {}, connection state: {}", request_id, m_state);
    m_requests.erase(request_id);

    if (timeout == std::cv_status::timeout) {
        return {nullptr, TIMEOUT_STR.data()};
    }

    if (res != nullptr) {
        return {ldns_pkt_ptr(res), std::nullopt};
    }

    return {nullptr, "Request failed (empty packet)"};
}

int dns_over_quic::bind_addr(int fd, int family) {
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> safe_res(nullptr, &freeaddrinfo);
    addrinfo *res, *rp;

    addrinfo hints{};
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    if (auto rv = getaddrinfo(nullptr, "0", &hints, &res); rv != 0) {
        errlog(m_log, "Getaddrinfo error: {}", gai_strerror(rv));
        return -1;
    }
    safe_res.reset(res);

    for (rp = res; rp; rp = rp->ai_next) {
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) != -1) {
            break;
        }
    }

    if (!rp) {
        errlog(m_log, "Could not bind");
        return -1;
    }

    sockaddr_in6 addr{0};
    socklen_t len = sizeof(sockaddr_storage);
    if (getsockname(fd, (sockaddr *)&addr, &len) == -1) {
        errlog(m_log, "Getsockname error: {}", evutil_socket_error_to_string(evutil_socket_geterror(fd)));
        return -1;
    }
    m_local_addr = ag::socket_address((sockaddr *)&addr);

    return 0;
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
            errlog(m_log, "Ngtcp2_conn_write_stream: {}", ngtcp2_strerror(nwrite));
            return NETWORK_ERR_FATAL;
        }

        if (nwrite == 0) {
            return 0;
        }

        m_send_buf.push(nwrite);

        if (auto rv = send_packet(); rv != NETWORK_ERR_OK) {
            return rv;
        }
    }
}

int dns_over_quic::send_packet() {
    if (m_sock_state.connected) {
        return send_packet_connected();
    } else {
        return send_packet_not_connected();
    }
}

int dns_over_quic::send_packet_connected() {
    ssize_t nwrite = 0;

    nwrite = send(m_sock_state.fd, (const char *)m_send_buf.rpos(), m_send_buf.size(), 0);

    if (nwrite < 0) {
        int err = evutil_socket_geterror(m_sock_state.fd);
        tracelog(m_log, "Sending packet error: {}", evutil_socket_error_to_string(err));
        if (ag::utils::socket_error_is_eagain(err)) {
            return NETWORK_ERR_SEND_BLOCKED;
        }
    }

    m_send_buf.reset();

    return nwrite >= 0 ? NETWORK_ERR_OK : NETWORK_ERR_DROP_CONN;
}

int dns_over_quic::send_packet_not_connected() {
    ssize_t nwrite = 0;

    for (auto it = m_current_addresses.begin(); it != m_current_addresses.end(); ) {
        if (auto error = bind_socket_to_if(m_sock_state.fd, *it)) {
            warnlog(m_log, "Failed to bind socket to interface: {}", *error);
            return NETWORK_ERR_FATAL;
        }
        nwrite = sendto(m_sock_state.fd, (const char *)m_send_buf.rpos(), (int)m_send_buf.size(),
                            0, it->c_sockaddr(), it->c_socklen());

        if (nwrite < 0) {
            int err = evutil_socket_geterror(m_sock_state.fd);
            tracelog(m_log, "Sending packet to {} error: {}", it->str().c_str(), evutil_socket_error_to_string(err));
            if (ag::utils::socket_error_is_eagain(err)) {
                return NETWORK_ERR_SEND_BLOCKED;
            }
            disqualify_server_address(*it);
            it = m_current_addresses.erase(it);
        } else {
            tracelog(m_log, "Sending packet to {}", it->str().c_str());
            ++it;
        }
    }

    m_send_buf.reset();

    if (m_current_addresses.empty()) {
        return NETWORK_ERR_DROP_CONN;
    }

    struct timeval tv{};
    evtimer_pending(m_handshake_timer_event, &tv);
    if (!evutil_timerisset(&tv)) {
        tv = ag::utils::duration_to_timeval(m_options.timeout);
        evtimer_add(m_handshake_timer_event, &tv);
    }
    return NETWORK_ERR_OK;
}

int dns_over_quic::init_ssl_ctx() {
    m_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (m_ssl_ctx == nullptr) {
        return 1;
    }
    SSL_CTX_set_min_proto_version(m_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(m_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_quic_method(m_ssl_ctx, &quic_method);
    // setup our verifier
    SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_cert_verify_callback(m_ssl_ctx, dns_over_quic::ssl_verify_callback, nullptr);
    tls_session_cache::prepare_ssl_ctx(m_ssl_ctx);
    return 0;
}

int dns_over_quic::init_ssl() {
    if (m_ssl) {
        SSL_free(m_ssl);
    }
    m_ssl = SSL_new(m_ssl_ctx);
    if (m_ssl == nullptr) {
        return 1;
    }
    SSL_set_app_data(m_ssl, this);
    SSL_set_tlsext_host_name(m_ssl, m_server_name.c_str());
    SSL_set_connect_state(m_ssl);

    uint8_view alpn;
    if (m_version == AGNGTCP2_PROTO_VER_I00) {
        alpn = uint8_view(DQ_ALPN_I00, sizeof(DQ_ALPN_I00));
    } else if (m_version == AGNGTCP2_PROTO_VER_I02) {
        alpn = uint8_view(DQ_ALPN_I02, sizeof(DQ_ALPN_I02));
    }
    if (!alpn.empty()) {
        std::string tmp((char *)alpn.data() + 1, alpn.size() - 1);
        dbglog(m_log, "Selected ALPN: {}", tmp.c_str());
        SSL_set_alpn_protos(m_ssl, alpn.data(), alpn.size());
    } else {
        dbglog(m_log, "Selected ALPN: unknown");
    }

    m_tls_session_cache.prepare_ssl(m_ssl);

    if (ssl_session_ptr session = m_tls_session_cache.get_session()) {
        dbglog(m_log, "Using a cached TLS session");
        SSL_set_session(m_ssl, session.get()); // UpRefs the session
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

int dns_over_quic::on_read() {
    if (m_sock_state.connected) {
        if (int ret = on_read_connected(); ret != NETWORK_ERR_OK) {
            return ret;
        }
    } else {
        if (int ret = on_read_not_connected(); ret != NETWORK_ERR_OK) {
            return ret;
        }
    }

    update_idle_timer(false);

    return 0;
}

int dns_over_quic::on_read_connected() {
    std::array<uint8_t, 65536> buf{};
    ngtcp2_pkt_info pi;

    for (;;) {
        auto nread = recv(m_sock_state.fd, (char *)buf.data(), buf.size(), 0);
        if (nread == -1) {
            int err = evutil_socket_geterror(m_sock_state.fd);
            if (!ag::utils::socket_error_is_eagain(err)) {
                errlog(m_log, "Read socket (connected) failed: {}", evutil_socket_error_to_string(err));
            }
            break;
        }
        if (int ret = feed_data(&pi, buf.data(), nread); ret != NETWORK_ERR_OK) {
            return ret;
        }
    }

    return 0;
}

int dns_over_quic::on_read_not_connected() {
    std::array<uint8_t, 65536> buf{};
    sockaddr_storage su{};
    ngtcp2_pkt_info pi;

    while (!m_sock_state.connected) {
        su = {};
        socklen_t namelen = sizeof(su);
        auto nread = recvfrom(m_sock_state.fd, (char *)buf.data(), buf.size(), 0, (sockaddr *)&su, &namelen);

        if (nread == -1) {
            int err = evutil_socket_geterror(m_sock_state.fd);
            if (!ag::utils::socket_error_is_eagain(err)) {
                ag::socket_address sa{(sockaddr *)&su};
                errlog(m_log, "Received error for address {} failed: {}", sa.str(), evutil_socket_error_to_string(err));
                disqualify_server_address(sa);
                for (auto it = m_current_addresses.begin(); it != m_current_addresses.end(); it++) {
                    if (sa == it->socket_family_cast(sa.c_sockaddr()->sa_family)) {
                        m_current_addresses.erase(it);
                        break;
                    }
                }
                if (m_current_addresses.empty()) {
                    dbglog(m_log, "Disconnecting because no addresses left");
                    return NETWORK_ERR_FATAL;
                }
            }
            break;
        }

        ag::socket_address sa{(sockaddr *)&su};
        for (auto it = m_current_addresses.begin(); it != m_current_addresses.end(); ) {
            if (sa != it->socket_family_cast(sa.c_sockaddr()->sa_family)) {
                it = m_current_addresses.erase(it);
            } else {
                if (auto error = bind_socket_to_if(m_sock_state.fd, *it)) {
                    warnlog(m_log, "Failed to bind socket to interface: {}", *error);
                    return NETWORK_ERR_FATAL;
                }
                if (int res = connect(m_sock_state.fd, it->c_sockaddr(), it->c_socklen()); res != 0) {
                    warnlog(m_log, "Can't connect to {}",
                            ag::socket_address((sockaddr *)&su).str().c_str());
                } else {
                    infolog(m_log, "Connected to {}", ag::socket_address((sockaddr *)&su).str().c_str());
                    m_sock_state.connected = true;
                    break;
                }
                ++it;
            }
        }

        if (m_current_addresses.empty()) {
            warnlog(m_log, "Get packet from unknown address {}",
                    ag::socket_address((sockaddr *)&su).str().c_str());
            assert(0);
            return NETWORK_ERR_FATAL;
        }

        if (int ret = feed_data(&pi, buf.data(), nread); ret != NETWORK_ERR_OK) {
            return ret;
        }
    }

    return 0;
}

int dns_over_quic::feed_data(const ngtcp2_pkt_info *pi, uint8_t *data, size_t datalen) {
    auto path = ngtcp2_path{ {(size_t)m_local_addr.c_socklen(), (sockaddr *)m_local_addr.c_sockaddr()},
                             {(size_t)m_remote_addr_empty.c_socklen(), (sockaddr *)m_remote_addr_empty.c_sockaddr()} };

    auto initial_ts = get_tstamp();

    auto rv = ngtcp2_conn_read_pkt(m_conn, &path, pi, data, datalen, initial_ts);

    if (rv != 0) {
        errlog(m_log, "Ngtcp2_conn_read_pkt: {}", ngtcp2_strerror(rv));
        return rv;
    }

    return 0;
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
    case NGTCP2_CRYPTO_LEVEL_APP:
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

ngtcp2_tstamp dns_over_quic::get_tstamp() const {
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
    evtimer_del(doq->m_handshake_timer_event);
    doq->m_state = RUN;
    doq->update_idle_timer(true);
    doq->send_requests();
    return 0;
}

void dns_over_quic::ag_ngtcp2_settings_default(ngtcp2_settings &settings) {
    settings.max_udp_payload_size = m_max_pktlen;
    settings.cc_algo = NGTCP2_CC_ALGO_CUBIC;
    settings.initial_ts = get_tstamp();
    settings.initial_rtt = NGTCP2_DEFAULT_INITIAL_RTT / 2;

    auto &params = settings.transport_params;
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
    m_current_addresses.clear();

    int family = AF_INET6;
    evutil_socket_t fd;
    if (!m_config.ipv6_available ||
            (fd = create_dual_stack_socket()) == -1) {
        family = AF_INET;
        fd = create_ipv4_socket();
        if (fd == -1) {
            errlog(m_log, "Failed to create socket");
            return -1;
        }
    }
    unsigned int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&enable, sizeof(enable)) == -1) {
        warnlog(m_log, "Failed to make socket reusable: {}", evutil_socket_error_to_string(evutil_socket_geterror(fd)));
        evutil_closesocket(fd);
        return -1;
    }
    if (evutil_make_socket_nonblocking(fd) != 0) {
        errlog(m_log, "Failed to make socket non-blocking");
        evutil_closesocket(fd);
        return -1;
    }
    if (bind_addr(fd, family) != 0) {
        errlog(m_log, "Failed binding socket");
        evutil_closesocket(fd);
        return -1;
    }

    {
        std::scoped_lock l(m_global);
        // Getting one ipv6 address
        if (family == AF_INET6) {
            for (auto &cur : m_server_addresses) {
                if (cur.is_ipv6()) {
                    m_current_addresses.emplace_back(cur);
                    break;
                }
            }
        }

        // Getting one ipv4 address
        for (auto &cur : m_server_addresses) {
            if (cur.is_ipv4()) {
                m_current_addresses.emplace_back(cur.socket_family_cast(family));
                break;
            }
        }
    }

    for (auto &cur : m_current_addresses) {
        tracelog(m_log, "In this session will use the address: {}", cur.str().c_str());
    }

    auto path = ngtcp2_path{
            {(size_t)m_local_addr.c_socklen(), (sockaddr *)m_local_addr.c_sockaddr()},
            {(size_t)m_remote_addr_empty.c_socklen(), (sockaddr *)m_remote_addr_empty.c_sockaddr()}};

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    ag_ngtcp2_settings_default(settings);
    if (m_port == 784) {
        // https://tools.ietf.org/html/draft-ietf-dprive-dnsoquic-02#section-10.2.1
        m_version = AGNGTCP2_PROTO_VER_I00;
    } else {
        m_version = AGNGTCP2_PROTO_VER_I02;
    }

    RAND_bytes(m_static_secret.data(), m_static_secret.size());
    auto generate_cid = [](ngtcp2_cid &cid, size_t len) {
        cid.datalen = len;
        RAND_bytes(cid.data, cid.datalen);
    };
    ngtcp2_cid scid, dcid;
    generate_cid(scid, 17);
    generate_cid(dcid, 18);

    auto rv = ngtcp2_conn_client_new(&m_conn, &dcid, &scid, &path,
                                     m_version, &m_callbacks, &settings, nullptr, this);
    if (rv != 0) {
        errlog(m_log, "Failed creation ngtcp2_conn: {}", ngtcp2_strerror(rv));
        return -1;
    }

    if (init_ssl() != 0) {
        errlog(m_log, "Failed creation SSL");
        return -1;
    }
    ngtcp2_conn_set_tls_native_handle(m_conn, m_ssl);

    update_idle_timer(true);

    m_read_event = event_new(m_loop->c_base(), fd, (EV_TIMEOUT | EV_READ | EV_PERSIST), this->read_cb, this);
    event_add(m_read_event, nullptr);
    m_sock_state.fd = fd;

    if (int ret = on_write(); ret != NETWORK_ERR_OK) {
        return ret;
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
    event_base_once(m_loop->c_base(), -1, EV_TIMEOUT, [](evutil_socket_t, short, void *arg){
        auto *func = (std::function<void()> *) arg;
        (*func)();
        delete func;
    }, new std::function(std::move(f)), nullptr);
}

void dns_over_quic::process_reply(int64_t request_id, const uint8_t *request_data, size_t request_data_len) {
    std::lock_guard lg(m_global);
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
    if (m_conn) {
        ngtcp2_conn_del(m_conn);
        m_conn = nullptr;
    }

    if (m_read_event) {
        event_del(m_read_event);
        event_free(m_read_event);
        m_read_event = nullptr;
    }

    evutil_closesocket(m_sock_state.fd);
    m_sock_state.fd = -1;
    m_sock_state.connected = false;

    if (m_ssl) {
        SSL_free(m_ssl);
        m_ssl = nullptr;
    }

    std::lock_guard l(m_global);
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
        tv = ag::utils::duration_to_timeval(ceil<microseconds>(timeout_ns));
    }
    evtimer_del(m_retransmit_timer_event);
    evtimer_add(m_retransmit_timer_event, &tv);
}

int dns_over_quic::ssl_verify_callback(X509_STORE_CTX *ctx, void *arg) {
    (void)arg;

    SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    auto doq = (dns_over_quic *)SSL_get_app_data(ssl);

    if (doq->m_config.cert_verifier == nullptr) {
        dbglog(doq->m_log, "Cannot verify certificate due to verifier is not set");
        return 0;
    }

    if (auto err = doq->m_config.cert_verifier->verify(ctx, SSL_get_servername(ssl, SSL_get_servername_type(ssl)));
            err.has_value()) {
        dbglog(doq->m_log, "Failed to verify certificate: {}", err.value());
        return 0;
    }

    tracelog(doq->m_log, "Verified successfully");

    return 1;
}

void dns_over_quic::disqualify_server_address(const socket_address &server_address) {
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
            return NGTCP2_CRYPTO_LEVEL_APP;
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
        intmax_t effective_idle_timeout = ngtcp2_conn_get_idle_expiry(m_conn) - get_tstamp();
        if (effective_idle_timeout > 0) {
            value = ceil<milliseconds>(nanoseconds{effective_idle_timeout});
            tracelog(m_log, "Idle timer reset with long timeout, {} left", value);
        }
    } else {
        value = m_options.timeout * 2;
        if (!reset) {
            milliseconds pending = ceil<milliseconds>(get_event_remaining_timeout(m_idle_timer_event));
            if (pending <= value) {
                tracelog(m_log, "Idle timer unchanged, {} left", pending);
                return;
            } else {
                tracelog(m_log, "Idle timer reduced from {} to short timeout, {} left", pending, value);
            }
        } else {
            tracelog(m_log, "Idle timer reset with short timeout, {} left", value);
        }
    }

    timeval tv = ag::utils::duration_to_timeval(value);
    evtimer_add(m_idle_timer_event, &tv);
}
