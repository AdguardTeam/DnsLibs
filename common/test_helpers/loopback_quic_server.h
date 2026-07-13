#pragma once

// In-process DNS-over-QUIC (DoQ, RFC 9250) responder bound to 127.0.0.1. It is
// the first server-side QUIC/TLS responder in this repo: there is no in-tree
// code that calls `ngtcp2_conn_server_new` or
// `ngtcp2_crypto_boringssl_configure_server_context`, so this header builds the
// server-side QUIC transport from scratch, following the reference
// implementation in native_libs_common (`http/test/http3_server_side.cpp`).
//
// DoQ selects ALPN "doq" (matching DoqUpstream::RFC9250_ALPN) and frames DNS
// messages with a 2-byte length prefix over a single bidirectional QUIC stream:
// the client opens a bidi stream, writes [2-byte len][DNS query], and closes
// its write side (FIN); the server parses the query, invokes the handler, and
// writes [2-byte len][DNS reply] back on the same stream with FIN.
//
// The server exposes a `QuicMode` enum selecting the application protocol:
//   - DOQ  : RFC 9250 2-byte-length stream framing (raw QUIC, no nghttp3).
//   - DOH3 : HTTP/3 over QUIC via `Http3Server::accept()`. The Http3Server
//            manages its own `ngtcp2_conn` + TLS; the loopback server only
//            feeds datagrams to `input()` and calls `flush()`/`handle_expiry()`.
//            DoH3 request handling is identical to the DoH server: GET
//            `<path>?dns=<base64url>` → `decode_doh_query` → handler →
//            `submit_response` + `submit_body(eof=true)`.
//
// The TLS certificate/key pair comes from test_certificates.h (Task 1):
// `load_server_ssl_ctx()` provides a `TLS_server_method()` context with the
// self-signed cert/key loaded; this header then calls
// `ngtcp2_crypto_boringssl_configure_server_context` on it to install the QUIC
// TLS method, and installs the ALPN select callback (DoQ or h3). Clients use
// `TestCertificateVerifier{ACCEPT_ALL}` to accept the loopback cert.
//
// NOTE: this header is intended for inclusion by test targets that already
// link ngtcp2 + OpenSSL + libevent transitively (via `upstream`), which
// `common/` cannot do. The header itself lives in `common/test_helpers/` so
// every consuming test target can reuse it.

#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <optional>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#define NOCRYPT
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#ifdef OPENSSL_IS_BORINGSSL
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#else
#include <ngtcp2/ngtcp2_crypto_quictls.h>
#endif

#include "common/http/headers.h"
#include "common/http/http3.h"
#include "common/logger.h"
#include "common/net_utils.h"
#include "common/socket_address.h"
#include "common/utils.h"
#include "dns/common/dns_defs.h"

#include "loopback_dns_server.h" // detail:: socket helpers + build_dns_reply
#include "loopback_doh_server.h" // detail::decode_doh_query (?dns= parsing)
#include "test_certificates.h"   // load_server_ssl_ctx()

namespace ag::test::detail {

// ALPN for DNS-over-QUIC (RFC 9250). Matches DoqUpstream::RFC9250_ALPN.
inline static constexpr std::string_view DOQ_ALPN = "doq";

// ALPN for DNS-over-HTTPS/3 (HTTP/3 over QUIC). Matches the DohUpstream client
// offer when the upstream URL uses the "h3://" scheme.
inline static constexpr std::string_view DOH3_ALPN = "h3";

// QUIC version offered/answered (QUIC v1, the only version DoqUpstream uses).
inline static constexpr uint32_t QUIC_VERSION = NGTCP2_PROTO_VER_V1;

// Server source Connection ID length. RFC 9000 allows 1..NGTCP2_MAX_CIDLEN;
// use the maximum to maximize entropy for per-peer hashing.
inline static constexpr size_t SV_SCIDLEN = NGTCP2_MAX_CIDLEN;

// Maximum UDP datagram payload the server emits / advertises. Matches the
// Http3Settings default (1350) which is safe for a typical loopback MTU.
inline static constexpr size_t MAX_PKTLEN = 1350;

// Connection idle timeout (ns). Loopback test runs are short; 30s is ample and
// keeps a dropped connection from lingering.
inline static constexpr ngtcp2_duration IDLE_TIMEOUT_NS = 30 * NGTCP2_SECONDS;

// Period of the worker's expiry/tick timer. Drives ngtcp2 retransmits and
// flushes pending stream replies when no inbound datagrams arrive. Well below
// the handshake retransmit interval so the loopback handshake stays snappy.
inline static constexpr int64_t TICK_USEC = 50 * 1000;

// Receive buffer big enough for the largest possible UDP datagram (QUIC may
// coalesce several packets into one datagram up to the UDP max).
inline static constexpr size_t RECV_BUF_SIZE = 65535;

// Once-per-process init of libevent's threading support so that
// `event_base_loopexit` can wake the worker thread from `stop()`. Mirrors the
// reference (`http3_server_side.cpp`). Runs at first use.
inline void ensure_evthread() {
    static const int g_initialized = []() {
#ifdef _WIN32
        return evthread_use_windows_threads();
#else
        return evthread_use_pthreads();
#endif
    }();
    (void) g_initialized;
}

// Monotonic timestamp (ns since epoch) for ngtcp2, matching DoqUpstream's
// get_tstamp() on non-Linux platforms (steady_clock does not advance while the
// system sleeps, which is acceptable for a loopback test server).
inline ngtcp2_tstamp get_tstamp() {
    return static_cast<ngtcp2_tstamp>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
                    .count());
}

} // namespace ag::test::detail

namespace ag::test {

class LoopbackQuicServer {
public:
    // Selects the application protocol negotiated over the shared QUIC
    // transport. DOQ uses RFC 9250 2-byte stream framing (raw QUIC). DOH3
    // layers HTTP/3 on top via `Http3Server::accept()`, handling `?dns=` DoH
    // GET requests.
    enum class QuicMode { DOQ, DOH3 };

    using Handler = detail::DnsReplyHandler;

    explicit LoopbackQuicServer(Handler handler, QuicMode mode = QuicMode::DOQ)
            : m_handler(std::move(handler))
            , m_mode(mode) {
    }

    ~LoopbackQuicServer() {
        stop();
    }

    LoopbackQuicServer(const LoopbackQuicServer &) = delete;
    LoopbackQuicServer &operator=(const LoopbackQuicServer &) = delete;

    // Binds 127.0.0.1:0 (UDP), configures the QUIC TLS server context + ALPN
    // (DoQ or h3), and starts the worker thread running an event_base loop.
    // Blocks until the ephemeral port is assigned, so address()/port() are
    // usable on return.
    void start() {
        if (m_running.load()) {
            return;
        }
        detail::ensure_evthread();

        m_log = ag::Logger{"QUIC test server"};

        // TLS server context: Task 1's cert/key pair, then install the QUIC
        // TLS method (BoringSSL) + the mode-specific ALPN select callback.
        m_ssl_ctx = load_server_ssl_ctx();
        if (m_ssl_ctx == nullptr) {
            errlog(m_log, "Failed to load server SSL_CTX");
            return;
        }
#ifdef OPENSSL_IS_BORINGSSL
        if (ngtcp2_crypto_boringssl_configure_server_context(m_ssl_ctx.get()) != 0) {
#else
        if (ngtcp2_crypto_quictls_configure_server_context(m_ssl_ctx.get()) != 0) {
#endif
            errlog(m_log, "Failed to configure QUIC TLS server context");
            m_ssl_ctx.reset();
            return;
        }
        if (m_mode == QuicMode::DOQ) {
            SSL_CTX_set_alpn_select_cb(m_ssl_ctx.get(), alpn_select_doq_cb, nullptr);
        } else {
            SSL_CTX_set_alpn_select_cb(m_ssl_ctx.get(), alpn_select_h3_cb, nullptr);
        }

        // Bind a non-blocking UDP socket on the loopback, ephemeral port.
        m_fd = detail::open_dgram_socket();
        if (m_fd == detail::invalid_socket()) {
            errlog(m_log, "Failed to create UDP socket");
            m_ssl_ctx.reset();
            return;
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(m_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
            errlog(m_log, "Failed to bind UDP socket: {}", evutil_socket_error_to_string(evutil_socket_geterror(m_fd)));
            detail::close_fd(m_fd);
            m_fd = detail::invalid_socket();
            m_ssl_ctx.reset();
            return;
        }
        set_nonblocking(m_fd);
        auto bound = ag::utils::get_local_address(m_fd);
        m_bound_addr = bound.value_or(ag::SocketAddress{"127.0.0.1", detail::get_port(m_fd)});
        m_port = m_bound_addr.port();
        m_send_buf.resize(detail::MAX_PKTLEN);

        // event_base + persistent read event + periodic tick timer. Both
        // feed `serve()` (drain socket + drive expiry + flush).
        m_base.reset(event_base_new());
        m_read_event.reset(event_new(m_base.get(), m_fd, EV_READ | EV_PERSIST, &LoopbackQuicServer::on_readable, this));
        m_tick_event.reset(event_new(m_base.get(), -1, EV_PERSIST, &LoopbackQuicServer::on_tick, this));
        (void) event_add(m_read_event.get(), nullptr);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = static_cast<long>(detail::TICK_USEC);
        (void) event_add(m_tick_event.get(), &tv);

        m_running.store(true);
        m_worker = std::thread([this] {
            event_base_loop(m_base.get(), EVLOOP_NO_EXIT_ON_EMPTY);
        });
        infolog(m_log, "Bound to {}", m_bound_addr.str());
    }

    // Stops the worker thread and tears down the socket + TLS context + all
    // sessions. Idempotent. `event_base_loopexit` wakes the worker (safe
    // cross-thread once evthread is initialized); sessions are destroyed only
    // after the worker joins, so no ngtcp2_conn is touched concurrently.
    void stop() {
        if (!m_running.exchange(false)) {
            return;
        }
        event_base_loopexit(m_base.get(), nullptr);
        if (m_worker.joinable()) {
            m_worker.join();
        }
        m_sessions.clear();
        m_read_event.reset();
        m_tick_event.reset();
        detail::close_fd(m_fd);
        m_fd = detail::invalid_socket();
        m_base.reset();
        m_ssl_ctx.reset();
    }

    // "quic://127.0.0.1:<port>" (DoQ) or "h3://127.0.0.1:<port>/dns-query"
    // (DoH3) — ready to use as an upstream address.
    std::string address() const {
        if (m_mode == QuicMode::DOH3) {
            return AG_FMT("h3://127.0.0.1:{}/dns-query", m_port);
        }
        return AG_FMT("quic://127.0.0.1:{}", m_port);
    }

    uint16_t port() const {
        return m_port;
    }

private:
    // Per-peer QUIC connection state. Allocated on the first datagram from a
    // peer; destroyed when the connection errors out or the server stops.
    struct QuicSession {
        LoopbackQuicServer *server;
        ag::SocketAddress peer;
        ag::UniquePtr<ngtcp2_conn, ngtcp2_conn_del> conn;
        // Declared before `conn` so `conn` is destroyed first (ngtcp2_conn_del
        // must run while the SSL object is still alive).
        ag::UniquePtr<SSL, &SSL_free> ssl;
        ngtcp2_crypto_conn_ref conn_ref;
        std::array<uint8_t, 32> static_secret{};
        bool handshake_completed = false;

        // Accumulated inbound bytes per stream until FIN (DoQ frames may arrive
        // in multiple stream-data callbacks).
        std::unordered_map<int64_t, std::vector<uint8_t>> stream_bufs;

        // Stream replies awaiting/being written: [2-byte len][DNS wire bytes].
        // Kept alive (in `sent`) until the stream is closed so the data stays
        // valid until ngtcp2 acknowledges it (per writev_stream contract).
        std::unordered_map<int64_t, std::vector<uint8_t>> sent;
        std::unordered_map<int64_t, size_t> write_offset;
        std::deque<int64_t> pending_write;

        // DoH3 mode: the HTTP/3 server manages its own ngtcp2_conn + TLS
        // internally. Null in DoQ mode. Allocated in register_session() when
        // the first packet from a new peer is accepted by Http3Server::accept().
        std::unique_ptr<ag::http::Http3Server> http3_server;

        explicit QuicSession(LoopbackQuicServer *srv, ag::SocketAddress p)
                : server(srv)
                , peer(std::move(p)) {
            conn_ref.get_conn = &QuicSession::get_conn;
            conn_ref.user_data = this;
        }

        static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *ref) {
            return static_cast<QuicSession *>(ref->user_data)->conn.get();
        }
    };

    static void set_nonblocking(detail::socket_type s) {
        if (s == detail::invalid_socket()) {
            return;
        }
#ifdef _WIN32
        u_long flags = 1;
        (void) ioctlsocket(s, FIONBIO, &flags);
#else
        int flags = fcntl(s, F_GETFL, 0);
        if (flags != -1) {
            (void) fcntl(s, F_SETFL, flags | O_NONBLOCK);
        }
#endif
    }

    // ALPN select callback: always selects "doq" from the client's offer.
    static int alpn_select_doq_cb(SSL *, const unsigned char **out, unsigned char *outlen, const unsigned char *client,
            unsigned int client_len, void *) {
        // ALPN wire format: a sequence of (1-byte length + protocol) entries.
        unsigned int i = 0;
        while (i < client_len) {
            unsigned char plen = client[i];
            if (i + 1u + plen > client_len) {
                break;
            }
            if (plen == detail::DOQ_ALPN.size() && std::memcmp(client + i + 1, detail::DOQ_ALPN.data(), plen) == 0) {
                *out = client + i + 1;
                *outlen = plen;
                return SSL_TLSEXT_ERR_OK;
            }
            i += 1u + static_cast<unsigned int>(plen);
        }
        return SSL_TLSEXT_ERR_NOACK;
    }

    // ALPN select callback: always selects "h3" from the client's offer.
    static int alpn_select_h3_cb(SSL *, const unsigned char **out, unsigned char *outlen, const unsigned char *client,
            unsigned int client_len, void *) {
        unsigned int i = 0;
        while (i < client_len) {
            unsigned char plen = client[i];
            if (i + 1u + plen > client_len) {
                break;
            }
            if (plen == detail::DOH3_ALPN.size() && std::memcmp(client + i + 1, detail::DOH3_ALPN.data(), plen) == 0) {
                *out = client + i + 1;
                *outlen = plen;
                return SSL_TLSEXT_ERR_OK;
            }
            i += 1u + static_cast<unsigned int>(plen);
        }
        return SSL_TLSEXT_ERR_NOACK;
    }

    // --- libevent callbacks (worker thread) ---

    static void on_readable(evutil_socket_t, short, void *arg) {
        static_cast<LoopbackQuicServer *>(arg)->serve();
    }

    static void on_tick(evutil_socket_t, short, void *arg) {
        static_cast<LoopbackQuicServer *>(arg)->serve();
    }

    // Drain the UDP socket, then drive expiry + flush for every session,
    // then sweep dead peers. sweep_dead() runs after serve_sessions() (not
    // inside flush_session) so that on_close callbacks fired during flush()
    // can safely mark peers dead without invalidating the m_sessions iterator.
    void serve() {
        drain_socket();
        serve_sessions();
        sweep_dead();
    }

    // recvfrom loop until EAGAIN, feeding each datagram to its session.
    void drain_socket() {
        for (;;) {
            sockaddr_storage peer_ss{};
            detail::socklen_type peer_len = sizeof(peer_ss);
#ifdef _WIN32
            int n = ::recvfrom(m_fd, reinterpret_cast<char *>(m_recv_buf.data()), static_cast<int>(m_recv_buf.size()),
                    0, reinterpret_cast<sockaddr *>(&peer_ss), &peer_len);
#else
            ssize_t n = ::recvfrom(
                    m_fd, m_recv_buf.data(), m_recv_buf.size(), 0, reinterpret_cast<sockaddr *>(&peer_ss), &peer_len);
#endif
            if (n <= 0) {
                int err = evutil_socket_geterror(m_fd);
                if (!ag::utils::socket_error_is_eagain(err) && err != 0) {
                    dbglog(m_log, "recvfrom error: {} ({})", evutil_socket_error_to_string(err), err);
                }
                break;
            }
            auto peer = ag::SocketAddress{reinterpret_cast<const sockaddr *>(&peer_ss)};
            on_packet(peer, {m_recv_buf.data(), static_cast<size_t>(n)});
        }
    }

    // Look up or create the session for `peer`, then feed the datagram.
    void on_packet(const ag::SocketAddress &peer, Uint8View packet) {
        auto it = m_sessions.find(peer);
        if (it == m_sessions.end()) {
            QuicSession *session = register_session(peer, packet);
            if (session == nullptr) {
                return; // not a valid Initial; ignore
            }
            feed_packet(*session, packet);
        } else {
            feed_packet(*it->second, packet);
        }
    }

    void serve_sessions() {
        ngtcp2_tstamp now = detail::get_tstamp();
        for (auto &[peer, session_ptr] : m_sessions) {
            QuicSession &s = *session_ptr;
            if (m_mode == QuicMode::DOH3) {
                if (s.http3_server == nullptr) {
                    continue;
                }
                auto err = s.http3_server->handle_expiry();
                if (err != nullptr) {
                    dbglog(m_log, "[{}] http3 handle_expiry: {}", peer.str(), err->str());
                }
                flush_session(s);
            } else {
                if (s.conn == nullptr) {
                    continue;
                }
                int rv = ngtcp2_conn_handle_expiry(s.conn.get(), now);
                if (rv != 0 && rv != NGTCP2_ERR_IDLE_CLOSE) {
                    dbglog(m_log, "[{}] handle_expiry: {}", peer.str(), ngtcp2_strerror(rv));
                }
                flush_session(s);
            }
        }
    }

    // Create a new server-side ngtcp2_conn + per-connection SSL for `peer`. The
    // datagram must be a valid QUIC Initial (`ngtcp2_accept`); the client's
    // Initial source CID becomes the server's DCID, and the client's original
    // DCID is echoed in transport params (QUIC v1 integrity check). In DoH3
    // mode, the ngtcp2_conn + TLS are managed by Http3Server::accept() instead.
    QuicSession *register_session(const ag::SocketAddress &peer, Uint8View first_pkt) {
        ngtcp2_pkt_hd hd{};
        if (ngtcp2_accept(&hd, first_pkt.data(), first_pkt.size()) != 0) {
            dbglog(m_log, "[{}] not a valid QUIC Initial", peer.str());
            return nullptr;
        }

        if (m_mode == QuicMode::DOH3) {
            return register_session_doh3(peer, first_pkt);
        }

        auto session = std::make_unique<QuicSession>(this, peer);
        QuicSession *sp = session.get();

        RAND_bytes(sp->static_secret.data(), static_cast<int>(sp->static_secret.size()));

        ngtcp2_cid scid{};
        scid.datalen = detail::SV_SCIDLEN;
        RAND_bytes(scid.data, static_cast<int>(scid.datalen));

        ngtcp2_path path{};
        path.local.addr = const_cast<sockaddr *>(m_bound_addr.c_sockaddr());
        path.local.addrlen = m_bound_addr.c_socklen();
        path.remote.addr = const_cast<sockaddr *>(peer.c_sockaddr());
        path.remote.addrlen = peer.c_socklen();

        ngtcp2_settings settings;
        ngtcp2_settings_default(&settings);
        settings.initial_ts = detail::get_tstamp();
        settings.cc_algo = NGTCP2_CC_ALGO_CUBIC;
        settings.max_tx_udp_payload_size = detail::MAX_PKTLEN;

        ngtcp2_transport_params params;
        ngtcp2_transport_params_default(&params);
        params.initial_max_stream_data_bidi_local = 256 * 1024;
        params.initial_max_stream_data_bidi_remote = 256 * 1024;
        params.initial_max_stream_data_uni = 256 * 1024;
        params.initial_max_data = 1 * 1024 * 1024;
        params.initial_max_streams_bidi = 1024;
        params.initial_max_streams_uni = 0;
        params.max_idle_timeout = detail::IDLE_TIMEOUT_NS;
        params.active_connection_id_limit = 7;
        params.original_dcid = hd.dcid;
        params.original_dcid_present = 1;
        params.stateless_reset_token_present = 1;
        if (ngtcp2_crypto_generate_stateless_reset_token(
                    params.stateless_reset_token, sp->static_secret.data(), sp->static_secret.size(), &scid)
                != 0) {
            errlog(m_log, "[{}] failed to generate stateless reset token", peer.str());
            return nullptr;
        }

        ngtcp2_callbacks callbacks = make_callbacks();

        ngtcp2_conn *conn_raw = nullptr;
        int rv = ngtcp2_conn_server_new(
                &conn_raw, &hd.scid, &scid, &path, hd.version, &callbacks, &settings, &params, nullptr, sp);
        if (rv != 0) {
            errlog(m_log, "[{}] ngtcp2_conn_server_new: {}", peer.str(), ngtcp2_strerror(rv));
            return nullptr;
        }
        sp->conn.reset(conn_raw);

        sp->ssl.reset(SSL_new(m_ssl_ctx.get()));
        if (sp->ssl == nullptr) {
            errlog(m_log, "[{}] SSL_new failed", peer.str());
            return nullptr;
        }
        SSL_set_app_data(sp->ssl.get(), &sp->conn_ref);
        SSL_set_accept_state(sp->ssl.get());
        ngtcp2_conn_set_tls_native_handle(sp->conn.get(), sp->ssl.get());

        m_sessions.emplace(peer, std::move(session));
        tracelog(m_log, "[{}] new session (version {:#x})", peer.str(), hd.version);
        return sp;
    }

    // DoH3 session creation: Http3Server::accept() creates its own
    // ngtcp2_conn + TLS internally; the loopback server only feeds datagrams
    // to input() and calls flush()/handle_expiry(). Mirrors the reference
    // implementation's register_new_session.
    QuicSession *register_session_doh3(const ag::SocketAddress &peer, Uint8View first_pkt) {
        auto session = std::make_unique<QuicSession>(this, peer);
        QuicSession *sp = session.get();

        ag::http::QuicNetworkPath path{
                .local = m_bound_addr.c_sockaddr(),
                .local_len = m_bound_addr.c_socklen(),
                .remote = peer.c_sockaddr(),
                .remote_len = peer.c_socklen(),
        };

        ag::UniquePtr<SSL, &SSL_free> ssl{SSL_new(m_ssl_ctx.get())};
        if (ssl == nullptr) {
            errlog(m_log, "[{}] SSL_new failed", peer.str());
            return nullptr;
        }
        SSL_set_accept_state(ssl.get());

        auto make_result = ag::http::Http3Server::accept(
                ag::http::Http3Settings{}, make_h3_callbacks(sp), path, std::move(ssl), first_pkt);
        if (make_result.has_error()) {
            errlog(m_log, "[{}] Http3Server::accept: {}", peer.str(), make_result.error()->str());
            return nullptr;
        }
        sp->http3_server = std::move(make_result.value());

        m_sessions.emplace(peer, std::move(session));
        tracelog(m_log, "[{}] new DoH3 session", peer.str());
        return sp;
    }

    // Feed a datagram to the session's ngtcp2_conn (DoQ) or Http3Server
    // (DoH3), then flush. Errors close the session (mirrors the reference's
    // `read_pkt` → `handle_error` path, simplified: discard the peer on fatal
    // read errors).
    void feed_packet(QuicSession &s, Uint8View packet) {
        if (m_mode == QuicMode::DOH3) {
            feed_packet_doh3(s, packet);
            return;
        }

        ngtcp2_path path{};
        path.local.addr = const_cast<sockaddr *>(m_bound_addr.c_sockaddr());
        path.local.addrlen = m_bound_addr.c_socklen();
        path.remote.addr = const_cast<sockaddr *>(s.peer.c_sockaddr());
        path.remote.addrlen = s.peer.c_socklen();

        ngtcp2_tstamp now = detail::get_tstamp();
        ngtcp2_pkt_info pi{};
        int rv = ngtcp2_conn_read_pkt(s.conn.get(), &path, &pi, packet.data(), packet.size(), now);
        if (rv != 0) {
            dbglog(m_log, "[{}] ngtcp2_conn_read_pkt: {}", s.peer.str(), ngtcp2_strerror(rv));
            // Fatal: tear the offending peer's session down. Deferred via a
            // marker because we may be iterating m_sessions.
            m_dead_peers.push_back(s.peer);
            return;
        }
        flush_session(s);
    }

    // DoH3 datagram feed: calls Http3Server::input(). The on_request callback
    // (fired inside input) handles the ?dns= GET. flush() pushes the queued
    // response out via on_output → sendto. Mirrors the reference's
    // serve_connections loop.
    void feed_packet_doh3(QuicSession &s, Uint8View packet) {
        ag::http::QuicNetworkPath path{
                .local = m_bound_addr.c_sockaddr(),
                .local_len = m_bound_addr.c_socklen(),
                .remote = s.peer.c_sockaddr(),
                .remote_len = s.peer.c_socklen(),
        };
        auto input_result = s.http3_server->input(path, packet);
        if (input_result.has_error()) {
            dbglog(m_log, "[{}] http3 input: {}", s.peer.str(), input_result.error()->str());
            m_dead_peers.push_back(s.peer);
            return;
        }
        if (input_result.value() == ag::http::Http3Server::SEND_RETRY) {
            ngtcp2_pkt_hd hd{};
            if (ngtcp2_accept(&hd, packet.data(), packet.size()) == 0) {
                auto retry =
                        s.http3_server->prepare_retry(hd, s.peer.c_sockaddr(), s.peer.c_socklen(), packet.size() * 3);
                if (!retry.has_error()) {
                    ngtcp2_path retry_path{};
                    retry_path.local.addr = const_cast<sockaddr *>(m_bound_addr.c_sockaddr());
                    retry_path.local.addrlen = m_bound_addr.c_socklen();
                    retry_path.remote.addr = const_cast<sockaddr *>(s.peer.c_sockaddr());
                    retry_path.remote.addrlen = s.peer.c_socklen();
                    send_datagram(retry_path, {retry->data(), retry->size()});
                }
            }
        }
        flush_session(s);
    }

    // Write pending DoQ replies (with FIN), then flush any remaining framework
    // packets (acks / handshake / connection close). Drives the QUIC/TLS
    // handshake to completion on the server side.
    void flush_session(QuicSession &s) {
        if (m_mode == QuicMode::DOH3) {
            if (s.http3_server != nullptr) {
                auto err = s.http3_server->flush();
                if (err != nullptr) {
                    dbglog(m_log, "[{}] http3 flush: {}", s.peer.str(), err->str());
                }
            }
            return;
        }

        write_pending_replies(s);

        ngtcp2_tstamp now = detail::get_tstamp();
        for (;;) {
            ngtcp2_path_storage ps;
            ngtcp2_path_storage_zero(&ps);
            ngtcp2_pkt_info pi{};
            ngtcp2_ssize n =
                    ngtcp2_conn_write_pkt(s.conn.get(), &ps.path, &pi, m_send_buf.data(), m_send_buf.size(), now);
            if (n <= 0) {
                if (n < 0) {
                    dbglog(m_log, "[{}] ngtcp2_conn_write_pkt: {}", s.peer.str(), ngtcp2_strerror(static_cast<int>(n)));
                }
                break;
            }
            send_datagram(ps.path, {m_send_buf.data(), static_cast<size_t>(n)});
        }
    }

    // Drain every queued DoQ reply for the session via writev_stream. Uses no
    // WRITE_STREAM_FLAG_MORE (one STREAM frame per datagram) to keep the write
    // machine simple and avoid the WRITE_MORE in-progress-packet state. FIN is
    // requested on every call; ngtcp2 applies it only when a call fully
    // encodes the remaining data, which is exactly the DoQ "close stream after
    // reply" semantic.
    void write_pending_replies(QuicSession &s) {
        while (!s.pending_write.empty()) {
            int64_t stream_id = s.pending_write.front();
            s.pending_write.pop_front();
            auto buf_it = s.sent.find(stream_id);
            if (buf_it == s.sent.end()) {
                continue;
            }
            std::vector<uint8_t> &buf = buf_it->second;
            size_t &offset = s.write_offset[stream_id];
            ngtcp2_tstamp now = detail::get_tstamp();
            bool congested = false;
            while (offset < buf.size()) {
                ngtcp2_vec vec{buf.data() + offset, buf.size() - offset};
                uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
                ngtcp2_ssize ndatalen = -1;
                ngtcp2_path_storage ps;
                ngtcp2_path_storage_zero(&ps);
                ngtcp2_pkt_info pi{};
                ngtcp2_ssize n = ngtcp2_conn_writev_stream(s.conn.get(), &ps.path, &pi, m_send_buf.data(),
                        m_send_buf.size(), &ndatalen, flags, stream_id, &vec, 1, now);
                if (n == 0) {
                    congested = true; // congestion-limited; retry next flush
                    break;
                }
                if (n < 0) {
                    // STREAM_DATA_BLOCKED / STREAM_SHUT_WR / etc.: stop
                    // writing this stream; it will be retried or closed.
                    dbglog(m_log, "[{}] writev_stream({}): {}", s.peer.str(), stream_id,
                            ngtcp2_strerror(static_cast<int>(n)));
                    break;
                }
                send_datagram(ps.path, {m_send_buf.data(), static_cast<size_t>(n)});
                if (ndatalen > 0) {
                    offset += static_cast<size_t>(ndatalen);
                } else {
                    // Datagram carried framework only this round; let the
                    // write_pkt loop drain it and retry the stream later.
                    congested = true;
                    break;
                }
            }
            if (offset >= buf.size()) {
                s.write_offset.erase(stream_id); // FIN applied; data kept in `sent` until close
            } else if (congested) {
                s.pending_write.push_front(stream_id); // retry on next flush
                break;
            }
        }
    }

    void send_datagram(const ngtcp2_path &path, Uint8View data) {
        if (path.remote.addr == nullptr || data.empty()) {
            return;
        }
#ifdef _WIN32
        int r = ::sendto(m_fd, reinterpret_cast<const char *>(data.data()), static_cast<int>(data.size()), 0,
                path.remote.addr, static_cast<int>(path.remote.addrlen));
#else
        ssize_t r = ::sendto(m_fd, data.data(), data.size(), 0, path.remote.addr, path.remote.addrlen);
#endif
        if (r < 0 || static_cast<size_t>(r) != data.size()) {
            int err = evutil_socket_geterror(m_fd);
            dbglog(m_log, "sendto failed: {} ({})", evutil_socket_error_to_string(err), err);
        }
    }

    void sweep_dead() {
        if (m_dead_peers.empty()) {
            return;
        }
        for (const ag::SocketAddress &peer : m_dead_peers) {
            m_sessions.erase(peer);
        }
        m_dead_peers.clear();
    }

    // --- ngtcp2 callbacks (server-side) ---
    //
    // Most delegate to the ngtcp2-crypto defaults. The server-specific ones
    // (vs the DoqUpstream client) are `recv_client_initial` (the client leaves
    // it null) and `handshake_completed` (the client uses `handshake_confirmed`).
    // Field order matches `ngtcp2_callbacks` declaration order (C++20
    // designated initializers require declaration order).

    static ngtcp2_callbacks make_callbacks() {
        return ngtcp2_callbacks{
                .client_initial = ngtcp2_crypto_client_initial_cb,
                .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
                .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
                .handshake_completed = &LoopbackQuicServer::on_handshake_completed,
                .encrypt = ngtcp2_crypto_encrypt_cb,
                .decrypt = ngtcp2_crypto_decrypt_cb,
                .hp_mask = ngtcp2_crypto_hp_mask_cb,
                .recv_stream_data = &LoopbackQuicServer::on_recv_stream_data,
                .acked_stream_data_offset = &LoopbackQuicServer::on_acked_stream_data_offset,
                .stream_close = &LoopbackQuicServer::on_stream_close,
                .recv_retry = ngtcp2_crypto_recv_retry_cb,
                .rand = &LoopbackQuicServer::on_rand,
                .get_new_connection_id = &LoopbackQuicServer::on_get_new_connection_id,
                .update_key = &LoopbackQuicServer::on_update_key,
                .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
                .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
                .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
                .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
        };
    }

    static int on_handshake_completed(ngtcp2_conn *, void *user_data) {
        auto *s = static_cast<QuicSession *>(user_data);
        s->handshake_completed = true;
        tracelog(s->server->m_log, "[{}] handshake completed", s->peer.str());
        return 0;
    }

    static int on_recv_stream_data(ngtcp2_conn *, uint32_t flags, int64_t stream_id, uint64_t /*offset*/,
            const uint8_t *data, size_t datalen, void *user_data, void * /*stream_user_data*/) {
        auto *s = static_cast<QuicSession *>(user_data);
        s->server->handle_stream_data(*s, flags, stream_id, {data, datalen});
        return 0;
    }

    // DoQ framing (RFC 9250 §4.2.1): accumulate stream bytes until FIN, then
    // strip the 2-byte length prefix, parse the DNS query, invoke the handler,
    // and queue [2-byte len][reply] for sending on the same bidi stream.
    void handle_stream_data(QuicSession &s, uint32_t flags, int64_t stream_id, Uint8View chunk) {
        auto &buf = s.stream_bufs[stream_id];
        buf.insert(buf.end(), chunk.begin(), chunk.end());
        if ((flags & NGTCP2_STREAM_DATA_FLAG_FIN) == 0) {
            return;
        }
        std::vector<uint8_t> full = std::move(buf);
        s.stream_bufs.erase(stream_id);
        if (full.size() < 2) {
            dbglog(m_log, "[{}] stream {} too short ({})", s.peer.str(), stream_id, full.size());
            return;
        }
        uint16_t dns_len = static_cast<uint16_t>((static_cast<uint16_t>(full[0]) << 8) | full[1]);
        if (full.size() < size_t(2) + dns_len) {
            dbglog(m_log, "[{}] stream {} incomplete ({} < {})", s.peer.str(), stream_id, full.size(),
                    size_t(2) + dns_len);
            return;
        }
        auto reply = detail::build_dns_reply(m_handler, full.data() + 2, dns_len);
        if (!reply) {
            return; // handler dropped the query (e.g. timeout/negative test)
        }
        std::vector<uint8_t> framed;
        framed.reserve(2 + reply->size());
        uint16_t rlen = htons(static_cast<uint16_t>(reply->size()));
        framed.push_back(static_cast<uint8_t>(rlen >> 8));
        framed.push_back(static_cast<uint8_t>(rlen & 0xff));
        framed.insert(framed.end(), reply->begin(), reply->end());
        s.sent[stream_id] = std::move(framed);
        s.write_offset[stream_id] = 0;
        s.pending_write.push_back(stream_id);
    }

    static int on_acked_stream_data_offset(ngtcp2_conn *, int64_t /*stream_id*/, uint64_t /*offset*/,
            uint64_t /*datalen*/, void * /*user_data*/, void * /*stream_user_data*/) {
        // Reply buffers are retained in QuicSession::sent until the stream
        // closes (on_stream_close); nothing to free here per-ack.
        return 0;
    }

    static int on_stream_close(ngtcp2_conn *, uint32_t /*flags*/, int64_t stream_id, uint64_t /*app_error_code*/,
            void *user_data, void * /*stream_user_data*/) {
        auto *s = static_cast<QuicSession *>(user_data);
        s->sent.erase(stream_id);
        s->write_offset.erase(stream_id);
        s->stream_bufs.erase(stream_id);
        return 0;
    }

    static void on_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx * /*rand_ctx*/) {
        RAND_bytes(dest, static_cast<int>(destlen));
    }

    static int on_get_new_connection_id(
            ngtcp2_conn * /*conn*/, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data) {
        auto *s = static_cast<QuicSession *>(user_data);
        RAND_bytes(cid->data, static_cast<int>(cidlen));
        cid->datalen = cidlen;
        if (ngtcp2_crypto_generate_stateless_reset_token(token, s->static_secret.data(), s->static_secret.size(), cid)
                != 0) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    static int on_update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
            ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv, ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
            const uint8_t *current_rx_secret, const uint8_t *current_tx_secret, size_t secretlen,
            void * /*user_data*/) {
        std::array<uint8_t, 64> rx_key{};
        std::array<uint8_t, 64> tx_key{};
        if (ngtcp2_crypto_update_key(conn, rx_secret, tx_secret, rx_aead_ctx, rx_key.data(), rx_iv, tx_aead_ctx,
                    tx_key.data(), tx_iv, current_rx_secret, current_tx_secret, secretlen)
                != 0) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    // --- DoH3 (Http3Server) callbacks ---
    //
    // Mirror the reference implementation's Http3Server::Callbacks (the
    // on_request / on_output / on_close set). Only on_request, on_output, and
    // on_close are meaningful; the rest are no-ops because DoH3 GET requests
    // carry the query entirely in ?dns=.

    // Builds the Http3Server::Callbacks wired to this server's session +
    // on_output (sendto) path. Follows the reference's subset (8 of 12
    // callbacks); Http3Server handles nullptr for the omitted fields.
    static ag::http::Http3Server::Callbacks make_h3_callbacks(QuicSession *sp) {
        return ag::http::Http3Server::Callbacks{
                .arg = sp,
                .on_request = &LoopbackQuicServer::on_request_h3,
                .on_trailer_headers = &LoopbackQuicServer::on_trailer_headers_h3,
                .on_body = &LoopbackQuicServer::on_body_h3,
                .on_stream_read_finished = &LoopbackQuicServer::on_stream_read_finished_h3,
                .on_stream_closed = &LoopbackQuicServer::on_stream_closed_h3,
                .on_close = &LoopbackQuicServer::on_close_h3,
                .on_output = &LoopbackQuicServer::on_output_h3,
                .on_expiry_update = &LoopbackQuicServer::on_expiry_update_h3,
        };
    }

    // DoH3 request handler: identical to DoH (Task 5) — parse ?dns= → base64url
    // decode → handler → submit_response + submit_body(eof=true). The flush()
    // call (in feed_packet_doh3 / serve_sessions) pushes the response via
    // on_output → sendto.
    static void on_request_h3(void *arg, uint64_t stream_id, ag::http::Request request) {
        auto *s = static_cast<QuicSession *>(arg);
        auto query = ag::test::detail::decode_doh_query(request.path());
        if (!query) {
            ag::http::Response resp(ag::http::HTTP_3_0, 400);
            (void) s->http3_server->submit_response(stream_id, resp, true);
            return;
        }
        auto reply = ag::test::detail::build_dns_reply(s->server->m_handler, query->data(), query->size());
        if (!reply) {
            ag::http::Response resp(ag::http::HTTP_3_0, 500);
            (void) s->http3_server->submit_response(stream_id, resp, true);
            return;
        }
        ag::http::Response resp(ag::http::HTTP_3_0, 200);
        resp.headers().put("content-type", "application/dns-message");
        resp.headers().put("content-length", AG_FMT("{}", reply->size()));
        (void) s->http3_server->submit_response(stream_id, resp, false);
        (void) s->http3_server->submit_body(stream_id, {reply->data(), reply->size()}, true);
    }

    static void on_trailer_headers_h3(void *, uint64_t, ag::http::Headers) {
    }

    static void on_body_h3(void *, uint64_t, ag::Uint8View) {
        // DoH3 GET requests carry the query in ?dns=, not in the body.
    }

    static void on_stream_read_finished_h3(void *, uint64_t) {
    }

    static void on_stream_closed_h3(void *, uint64_t, int) {
    }

    // Mark the peer for deferred cleanup. The session is swept in serve()
    // after the m_sessions iteration completes, so the iterator is not
    // invalidated.
    static void on_close_h3(void *arg, uint64_t) {
        auto *s = static_cast<QuicSession *>(arg);
        s->server->m_dead_peers.push_back(s->peer);
    }

    // Convert QuicNetworkPath to ngtcp2_path and reuse the shared send_datagram
    // (sendto on the UDP socket).
    static void on_output_h3(void *arg, const ag::http::QuicNetworkPath &path, ag::Uint8View chunk) {
        auto *s = static_cast<QuicSession *>(arg);
        if (path.remote == nullptr || chunk.empty()) {
            return;
        }
        ngtcp2_path p{};
        p.local.addr = const_cast<sockaddr *>(path.local);
        p.local.addrlen = path.local_len;
        p.remote.addr = const_cast<sockaddr *>(path.remote);
        p.remote.addrlen = path.remote_len;
        s->server->send_datagram(p, chunk);
    }

    // The server's periodic tick (m_tick_event, 50 ms) already calls
    // handle_expiry() + flush() for every session, so the per-session expiry
    // timer is driven from the shared tick rather than a dedicated event.
    static void on_expiry_update_h3(void *, ag::Nanos) {
    }

    Handler m_handler;
    QuicMode m_mode;
    uint16_t m_port{0};
    ag::SocketAddress m_bound_addr;
    std::atomic_bool m_running{false};
    ag::Logger m_log{"QUIC test server"};

    detail::socket_type m_fd{detail::invalid_socket()};
    ag::UniquePtr<SSL_CTX, &SSL_CTX_free> m_ssl_ctx;

    ag::UniquePtr<event_base, &event_base_free> m_base;
    ag::UniquePtr<event, &event_free> m_read_event;
    ag::UniquePtr<event, &event_free> m_tick_event;
    std::thread m_worker;

    std::array<uint8_t, detail::RECV_BUF_SIZE> m_recv_buf{};
    std::vector<uint8_t> m_send_buf;

    std::unordered_map<ag::SocketAddress, std::unique_ptr<QuicSession>> m_sessions;
    std::vector<ag::SocketAddress> m_dead_peers;
};

} // namespace ag::test
