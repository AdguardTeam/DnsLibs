#pragma once

// In-process DNS-over-HTTPS (DoH) responder bound to 127.0.0.1. It layers an
// HTTP/1.1 or HTTP/2 responder on top of the LoopbackTlsServer TLS accept path
// (server-side BoringSSL), speaking RFC 8484 (GET <path>?dns=<base64url>,
// `application/dns-message` response body). The TLS certificate/key pair is
// provided by test_certificates.h (Task 1); clients use
// TestCertificateVerifier{ACCEPT_ALL} to accept it. Intended as a test double
// for DoH integration tests that should not depend on the public internet.
//
// The HTTP layer wraps the server counterparts (Http1Server/Http2Server) from
// native_libs_common -- the same headers the DohUpstream client consumes -- so
// a real DohUpstream can exchange against this local server entirely offline.
//
// API notes (verified against the native_libs_common headers):
//   - Http1Server: send_response(uint64_t, Response) + send_body(uint64_t,
//     Uint8View, bool eof). No flush(); on_output fires synchronously during
//     those calls. stream_id is uint64_t.
//   - Http2Server: make(settings, callbacks); submit_response(uint32_t,
//     Response, bool eof) + submit_body(uint32_t, Uint8View, bool eof) +
//     flush(). on_output fires during flush(). stream_id is uint32_t.
//
// The server negotiates ALPN `h2` or `http/1.1` (whichever the configuration
// selects from the client's offer of ["h2","http/1.1"], as set in
// DohUpstream::Http1Or2Connection::establish) and dispatches to the matching
// HTTP server class. The chosen protocol is controllable per instance via
// AlpnMode so tests can exercise each path.

#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <openssl/ssl.h>

#include "common/base64.h"
#include "common/http/headers.h"
#include "common/http/http1.h"
#include "common/http/http2.h"
#include "common/net_utils.h"
#include "common/utils.h"
#include "dns/common/dns_defs.h"

#include "loopback_dns_server.h" // detail:: socket helpers + build_dns_reply
#include "loopback_tls_server.h" // detail::ssl_send_exact (shared TLS plumbing)
#include "test_certificates.h"   // load_server_ssl_ctx()

namespace ag::test {

namespace detail {

// ALPN protocol strings for DNS-over-HTTPS (RFC 8484). Match the ALPN offer
// the DohUpstream client negotiates with.
inline static constexpr std::string_view DOH_ALPN_H2 = "h2";
inline static constexpr std::string_view DOH_ALPN_H1_1 = "http/1.1";

// Decodes the `?dns=` parameter from an HTTP request target (e.g.
// "/dns-query?dns=<base64url>") into raw DNS wire bytes. Returns nullopt if the
// parameter is absent or not valid base64url. This is the inverse of the DoH
// client's request encoder in DohUpstream::send_request.
inline std::optional<std::vector<uint8_t>> decode_doh_query(std::string_view path) {
    auto qpos = path.find('?');
    if (qpos == std::string_view::npos) {
        return std::nullopt;
    }
    std::string_view query = path.substr(qpos + 1);
    auto eqpos = query.find("dns=");
    if (eqpos == std::string_view::npos) {
        return std::nullopt;
    }
    std::string_view b64 = query.substr(eqpos + 4);
    // Stop at the next parameter (if any).
    if (auto amp = b64.find('&'); amp != std::string_view::npos) {
        b64 = b64.substr(0, amp);
    }
    return ag::decode_base64(b64, /*url_safe*/ true);
}

// HTTP/2 frame header size (RFC 9113 §4.1): 3-byte length + type + flags +
// 4-byte stream id.
inline static constexpr size_t H2_FRAME_HEADER_SIZE = 9;
inline static constexpr uint8_t H2_FRAME_TYPE_SETTINGS = 0x04;
inline static constexpr uint8_t H2_FLAG_SETTINGS_ACK = 0x01;

// Reorders HTTP/2 server output so the server's (non-ACK) SETTINGS frame --
// the connection preface (RFC 9113 §3.4) -- is emitted before any SETTINGS
// ACK. native_libs_common's Http2Server delays submitting its own SETTINGS
// until it has sent the SETTINGS ACK (in Http2Session::on_frame_send, the
// NGHTTP2_SETTINGS case calls submit_settings_impl()), so it emits
// ACK-then-SETTINGS, which nghttp2 clients reject with "expected SETTINGS
// frame". This shim buffers the session output until the server's SETTINGS
// frame is fully available, then emits it first (followed by the buffered ACK
// and any trailing bytes), after which all further output passes through
// unchanged. Frame boundaries are parsed robustly, so it works whether the
// transport delivers frames one-at-a-time or batched/split.
struct H2PrefaceReorderer {
    SSL *ssl = nullptr;
    std::vector<uint8_t> buf;
    bool done = false;

    void on_output(Uint8View chunk) {
        if (done) {
            (void) ssl_send_exact(ssl, chunk.data(), chunk.size());
            return;
        }
        buf.insert(buf.end(), chunk.begin(), chunk.end());
        maybe_flush();
    }

    void maybe_flush() {
        // Scan complete frames; find the first non-ACK SETTINGS frame.
        size_t p = 0;
        size_t settings_pos = buf.size(); // sentinel: not found
        size_t settings_end = 0;
        while (p + H2_FRAME_HEADER_SIZE <= buf.size()) {
            uint32_t flen = (uint32_t(buf[p]) << 16) | (uint32_t(buf[p + 1]) << 8) | uint32_t(buf[p + 2]);
            size_t fend = p + H2_FRAME_HEADER_SIZE + flen;
            if (fend > buf.size()) {
                break; // incomplete frame; wait for more bytes
            }
            uint8_t type = buf[p + 3];
            uint8_t flags = buf[p + 4];
            if (type == H2_FRAME_TYPE_SETTINGS && !(flags & H2_FLAG_SETTINGS_ACK)) {
                settings_pos = p;
                settings_end = fend;
                break;
            }
            p = fend;
        }
        if (settings_pos == buf.size()) {
            return; // keep buffering until the server SETTINGS arrives
        }
        // Emit: the non-ACK SETTINGS frame, then everything that preceded it
        // (the SETTINGS ACK), then everything that follows (remaining complete
        // frames + any trailing partial bytes), preserving the byte stream.
        std::vector<uint8_t> out;
        out.reserve(buf.size());
        out.insert(out.end(), buf.begin() + settings_pos, buf.begin() + settings_end);
        out.insert(out.end(), buf.begin(), buf.begin() + settings_pos);
        out.insert(out.end(), buf.begin() + settings_end, buf.end());
        (void) ssl_send_exact(ssl, out.data(), out.size());
        buf.clear();
        done = true;
    }
};

} // namespace detail

class LoopbackDohServer {
public:
    // Selects which ALPN the server negotiates from the client's offer of
    // ["h2","http/1.1"]. The DohUpstream client exposes no option to restrict
    // its ALPN offer, so the negotiated protocol is controlled from the server
    // side: PREFER_H2 -> HTTP/2 path, H1_ONLY -> HTTP/1.1 path.
    enum class AlpnMode {
        PREFER_H2,
        H1_ONLY,
    };

    using Handler = detail::DnsReplyHandler;

    explicit LoopbackDohServer(Handler handler, std::string path = "/dns-query", AlpnMode alpn = AlpnMode::PREFER_H2)
            : m_handler(std::move(handler))
            , m_path(std::move(path))
            , m_alpn(alpn) {
    }

    ~LoopbackDohServer() {
        stop();
    }

    LoopbackDohServer(const LoopbackDohServer &) = delete;
    LoopbackDohServer &operator=(const LoopbackDohServer &) = delete;

    // Binds 127.0.0.1:0, loads the server SSL_CTX, installs the ALPN select
    // callback, starts the accept thread. Blocks until the ephemeral port is
    // assigned, so address()/port() are usable on return.
    void start() {
        if (m_running.load()) {
            return;
        }
        detail::ensure_winsock();

        m_ssl_ctx = load_server_ssl_ctx();
        SSL_CTX_set_alpn_select_cb(m_ssl_ctx.get(), alpn_select_cb, &m_alpn);

        m_tcp_sock = detail::open_stream_socket();
        detail::set_reuseaddr(m_tcp_sock);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        (void) ::bind(m_tcp_sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
        m_port = detail::get_port(m_tcp_sock);
        (void) ::listen(m_tcp_sock, SOMAXCONN);
        m_running.store(true);
        m_thread = std::thread([this] {
            doh_loop();
        });
    }

    // Stops the accept thread and closes the listening socket. Idempotent.
    // Unlike the one-exchange-then-close DoT server, this DoH server keeps each
    // connection alive (HTTP keep-alive / H2 stream multiplexing) so the
    // client's trailing ALPN/SETTINGS acks are absorbed rather than RST'd on
    // close. stop() therefore also shuts down the active connection's socket
    // to interrupt a worker blocked on SSL_read, keeping the join deadlock-free.
    void stop() {
        if (!m_running.exchange(false)) {
            return;
        }
        detail::shutdown_socket(m_tcp_sock);
        detail::shutdown_socket(m_active_conn.load());
        detail::close_fd(m_tcp_sock);
        m_tcp_sock = detail::invalid_socket();
        if (m_thread.joinable()) {
            m_thread.join();
        }
        m_ssl_ctx.reset();
    }

    // "https://127.0.0.1:<port><path>" -- ready to use as an upstream address.
    std::string address() const {
        return AG_FMT("https://127.0.0.1:{}{}", m_port, m_path);
    }

    uint16_t port() const {
        return m_port;
    }

private:
    // Per-connection state handed to the HTTP server callbacks via `arg`.
    struct ConnContext {
        SSL *ssl;
        std::string request_path;
        uint64_t h1_stream_id = 0;
        uint32_t h2_stream_id = 0;
        bool request_received = false;
        detail::H2PrefaceReorderer h2_out; // used only by the HTTP/2 path
    };

    // ALPN select callback: selects the protocol per the configured AlpnMode.
    // `arg` points to the server's AlpnMode member.
    static int alpn_select_cb(SSL *, const unsigned char **out, unsigned char *outlen, const unsigned char *client,
            unsigned int client_len, void *arg) {
        auto mode = *static_cast<const AlpnMode *>(arg);
        // ALPN wire format: a sequence of (1-byte length + protocol) entries.
        auto match = [&](std::string_view proto) -> bool {
            unsigned int i = 0;
            while (i < client_len) {
                unsigned char plen = client[i];
                if (i + 1u + plen > client_len) {
                    break;
                }
                std::string_view p(reinterpret_cast<const char *>(client + i + 1), plen);
                if (p == proto) {
                    *out = client + i + 1;
                    *outlen = plen;
                    return true;
                }
                i += 1u + plen;
            }
            return false;
        };
        if (mode == AlpnMode::PREFER_H2 && match(detail::DOH_ALPN_H2)) {
            return SSL_TLSEXT_ERR_OK;
        }
        if (match(detail::DOH_ALPN_H1_1)) {
            return SSL_TLSEXT_ERR_OK;
        }
        return SSL_TLSEXT_ERR_NOACK;
    }

    // --- HTTP/1.1 callbacks ---

    static void on_request_h1(void *arg, uint64_t stream_id, http::Request request) {
        auto *c = static_cast<ConnContext *>(arg);
        c->h1_stream_id = stream_id;
        c->request_path = std::string(request.path());
        c->request_received = true;
    }

    static void on_trailer_headers_h1(void *, uint64_t, http::Headers) {
    }

    static void on_body_h1(void *, uint64_t, Uint8View) {
    }

    static void on_body_finished_h1(void *, uint64_t) {
    }

    static void on_stream_finished_h1(void *, uint64_t, int) {
    }

    static void on_output_h1(void *arg, Uint8View chunk) {
        auto *c = static_cast<ConnContext *>(arg);
        (void) detail::ssl_send_exact(c->ssl, chunk.data(), chunk.size());
    }

    // --- HTTP/2 callbacks ---

    static void on_request_h2(void *arg, uint32_t stream_id, http::Request request) {
        auto *c = static_cast<ConnContext *>(arg);
        c->h2_stream_id = stream_id;
        c->request_path = std::string(request.path());
        c->request_received = true;
    }

    static void on_trailer_headers_h2(void *, uint32_t, http::Headers) {
    }

    static void on_body_h2(void *, uint32_t, Uint8View) {
    }

    static void on_stream_read_finished_h2(void *, uint32_t) {
    }

    static void on_stream_closed_h2(void *, uint32_t, nghttp2_error_code) {
    }

    static void on_output_h2(void *arg, Uint8View chunk) {
        auto *c = static_cast<ConnContext *>(arg);
        c->h2_out.on_output(chunk);
    }

    // Builds the DoH wire reply for the captured request, or nullopt if the
    // ?dns= payload could not be decoded or the handler dropped the query.
    std::optional<std::vector<uint8_t>> build_reply(const ConnContext &c) const {
        auto query = detail::decode_doh_query(c.request_path);
        if (!query) {
            return std::nullopt;
        }
        return detail::build_dns_reply(m_handler, query->data(), query->size());
    }

    // Submits an HTTP/1.1 response (status line + headers then body with eof).
    // Content-Length is set explicitly so the client fires on_body_finished
    // deterministically (the inverse of how real DoH servers respond).
    void respond_h1(http::Http1Server *srv, ConnContext &c) {
        auto reply = build_reply(c);
        if (!reply) {
            http::Response resp(http::HTTP_1_1, 400); // NOLINT(*-magic-numbers)
            resp.status_string("Bad Request");
            (void) srv->send_response(c.h1_stream_id, resp);
            (void) srv->send_body(c.h1_stream_id, {}, true);
            return;
        }
        http::Response resp(http::HTTP_1_1, 200); // NOLINT(*-magic-numbers)
        resp.status_string("OK");
        resp.headers().put("Content-Type", "application/dns-message");
        resp.headers().put("Content-Length", AG_FMT("{}", reply->size()));
        (void) srv->send_response(c.h1_stream_id, resp);
        (void) srv->send_body(c.h1_stream_id, {reply->data(), reply->size()}, true);
    }

    // Submits an HTTP/2 response (HEADERS then DATA with end_stream). H2 uses
    // the end_stream flag (not Content-Length) to signal body completion;
    // content-length is still set for correctness/parity with real servers.
    void respond_h2(http::Http2Server *srv, ConnContext &c) {
        auto reply = build_reply(c);
        http::Response resp(http::HTTP_2_0,
                reply ? 200 : 400); // NOLINT(*-magic-numbers)
        resp.headers().put("content-type", "application/dns-message");
        if (!reply) {
            (void) srv->submit_response(c.h2_stream_id, resp, true);
            (void) srv->flush();
            return;
        }
        resp.headers().put("content-length", AG_FMT("{}", reply->size()));
        (void) srv->submit_response(c.h2_stream_id, resp, false);
        (void) srv->submit_body(c.h2_stream_id, {reply->data(), reply->size()}, true);
        (void) srv->flush();
    }

    // Handles a single TLS connection: reads the negotiated ALPN, dispatches to
    // the matching HTTP server, feeds decrypted bytes via SSL_read -> input(),
    // and writes response bytes via on_output -> SSL_write. The connection is
    // kept alive (one or more exchanges) so the client's trailing HTTP/2
    // SETTINGS acks are consumed instead of triggering a TCP RST on close. The
    // loop exits on client EOF/error, or when stop() shuts the socket down.
    void handle_connection(detail::socket_type conn) {
        m_active_conn.store(conn);

        ag::UniquePtr<SSL, &SSL_free> ssl{SSL_new(m_ssl_ctx.get())};
        if (ssl == nullptr) {
            detail::close_fd(conn);
            m_active_conn.store(detail::invalid_socket());
            return;
        }
        SSL_set_fd(ssl.get(), static_cast<int>(conn));
        SSL_set_accept_state(ssl.get());
        if (SSL_accept(ssl.get()) <= 0) {
            detail::close_fd(conn);
            m_active_conn.store(detail::invalid_socket());
            return;
        }

        const unsigned char *alpn = nullptr;
        unsigned int alpn_len = 0;
        SSL_get0_alpn_selected(ssl.get(), &alpn, &alpn_len);
        std::string_view alpn_sv(reinterpret_cast<const char *>(alpn), alpn_len);

        ConnContext ctx{ssl.get()};
        ctx.h2_out.ssl = ssl.get();

        if (alpn_sv == detail::DOH_ALPN_H2) {
            serve_h2(ssl.get(), ctx);
            // Http2Server destroyed here (in serve_h2); its destructor may
            // raise on_output (GOAWAY) while ssl is still valid.
        } else {
            serve_h1(ssl.get(), ctx);
        }

        (void) SSL_shutdown(ssl.get());
        detail::close_fd(conn);
        m_active_conn.store(detail::invalid_socket());
    }

    // HTTP/1.1 keep-alive exchange loop. on_output writes synchronously during
    // send_response/send_body, so no explicit flush is needed. After replying,
    // the loop reads the next pipelined request (or blocks until the client
    // closes / stop() interrupts).
    void serve_h1(SSL *ssl, ConnContext &ctx) {
        http::Http1Server::Callbacks cbs{
                .arg = &ctx,
                .on_request = on_request_h1,
                .on_trailer_headers = on_trailer_headers_h1,
                .on_body = on_body_h1,
                .on_body_finished = on_body_finished_h1,
                .on_stream_finished = on_stream_finished_h1,
                .on_output = on_output_h1,
        };
        http::Http1Server srv(cbs);
        std::vector<uint8_t> buf(detail::MAX_DNS_PACKET);
        while (m_running.load()) {
            int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
            if (n <= 0) {
                break;
            }
            if (srv.input({buf.data(), static_cast<size_t>(n)}).has_error()) {
                break;
            }
            if (std::exchange(ctx.request_received, false)) {
                respond_h1(&srv, ctx);
            }
        }
    }

    // HTTP/2 keep-alive exchange loop. on_output fires during flush(); input()
    // only queues outbound frames (SETTINGS/acks/responses), so flush() is
    // called after every input() to drain them to the wire. Keeping the
    // session alive lets the client's SETTINGS ack flow back and be consumed
    // rather than triggering a connection reset on close.
    void serve_h2(SSL *ssl, ConnContext &ctx) {
        auto server_res = http::Http2Server::make(http::Http2Settings{},
                http::Http2Server::Callbacks{
                        .arg = &ctx,
                        .on_request = on_request_h2,
                        .on_trailer_headers = on_trailer_headers_h2,
                        .on_body = on_body_h2,
                        .on_stream_read_finished = on_stream_read_finished_h2,
                        .on_stream_closed = on_stream_closed_h2,
                        .on_output = on_output_h2,
                });
        if (server_res.has_error()) {
            return;
        }
        auto &srv = server_res.value();
        std::vector<uint8_t> buf(detail::MAX_DNS_PACKET);
        while (m_running.load()) {
            int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
            if (n <= 0) {
                break;
            }
            if (srv->input({buf.data(), static_cast<size_t>(n)}).has_error()) {
                break;
            }
            (void) srv->flush();
            if (std::exchange(ctx.request_received, false)) {
                respond_h2(srv.get(), ctx);
            }
        }
    }

    // Single-threaded sequential accept loop (same deadlock-safety model as
    // LoopbackTlsServer::tls_loop): accept -> TLS handshake -> HTTP exchange
    // -> shutdown -> close, then loop.
    void doh_loop() {
        while (m_running.load()) {
            sockaddr_in client{};
            detail::socklen_type client_len = sizeof(client);
            detail::socket_type conn = ::accept(m_tcp_sock, reinterpret_cast<sockaddr *>(&client), &client_len);
            if (conn == detail::invalid_socket()) {
                break;
            }
            handle_connection(conn);
        }
    }

    Handler m_handler;
    std::string m_path;
    AlpnMode m_alpn;
    uint16_t m_port{0};
    std::atomic_bool m_running{false};
    detail::socket_type m_tcp_sock{detail::invalid_socket()};
    std::atomic<detail::socket_type> m_active_conn{detail::invalid_socket()};
    ag::UniquePtr<SSL_CTX, &SSL_CTX_free> m_ssl_ctx;
    std::thread m_thread;
};

} // namespace ag::test
