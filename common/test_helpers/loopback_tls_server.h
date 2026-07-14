#pragma once

// In-process DNS-over-TLS (DoT) responder bound to 127.0.0.1. It extends the
// LoopbackDnsServer pattern with server-side TLS (BoringSSL), speaking the
// DNS-over-TCP 2-byte length-prefix wire format over SSL_read/SSL_write. The
// TLS certificate/key pair is provided by test_certificates.h (Task 1);
// clients use TestCertificateVerifier{ACCEPT_ALL} to accept it. Intended as a
// test double for DoT integration tests that should not depend on the public
// internet.

#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <ldns/ldns.h>
#include <openssl/ssl.h>

#include "common/net_utils.h"
#include "dns/common/dns_defs.h"

#include "loopback_dns_server.h" // detail:: socket helpers + build_dns_reply
#include "test_certificates.h"   // load_server_ssl_ctx()

namespace ag::test::detail {

// ALPN protocol string for DNS-over-TLS (RFC 7858). Matches the DotUpstream
// client's ALPN offer (see upstream_dot.cpp, DOT_ALPN == "dot").
inline static constexpr std::string_view DOT_ALPN = "dot";

// Receives exactly `len` bytes from an established TLS connection. Returns
// false on EOF/error.
inline bool ssl_recv_exact(SSL *ssl, uint8_t *dst, size_t len) {
    while (len > 0) {
        int n = SSL_read(ssl, dst, static_cast<int>(len));
        if (n <= 0) {
            return false;
        }
        dst += static_cast<size_t>(n);
        len -= static_cast<size_t>(n);
    }
    return true;
}

// Sends exactly `len` bytes over an established TLS connection. Returns false
// on error.
inline bool ssl_send_exact(SSL *ssl, const uint8_t *src, size_t len) {
    while (len > 0) {
        int n = SSL_write(ssl, src, static_cast<int>(len));
        if (n <= 0) {
            return false;
        }
        src += static_cast<size_t>(n);
        len -= static_cast<size_t>(n);
    }
    return true;
}

// ALPN select callback: always selects the DoT ALPN ("dot"). The loopback
// server only speaks DoT, so unconditionally advertising it is correct.
inline int alpn_select_dot_cb(
        SSL *, const unsigned char **out, unsigned char *outlen, const unsigned char *, unsigned int, void *) {
    *out = reinterpret_cast<const unsigned char *>(DOT_ALPN.data());
    *outlen = static_cast<unsigned char>(DOT_ALPN.size());
    return SSL_TLSEXT_ERR_OK;
}

} // namespace ag::test::detail

namespace ag::test {

class LoopbackTlsServer {
public:
    using Handler = detail::DnsReplyHandler;

    explicit LoopbackTlsServer(Handler handler)
            : m_handler(std::move(handler)) {
    }

    ~LoopbackTlsServer() {
        stop();
    }

    LoopbackTlsServer(const LoopbackTlsServer &) = delete;
    LoopbackTlsServer &operator=(const LoopbackTlsServer &) = delete;

    // Binds 127.0.0.1:0, loads the server SSL_CTX, starts the accept thread.
    // Blocks until the ephemeral port is assigned, so address()/port() are
    // usable on return.
    void start() {
        if (m_running.load()) {
            return;
        }
        detail::ensure_winsock();

        m_ssl_ctx = load_server_ssl_ctx();
        // load_server_ssl_ctx() returns null when the test certificate material
        // could not be loaded (or SSL_CTX_new failed). Fail the test explicitly
        // instead of dereferencing a null SSL_CTX below. EXPECT_NE (not
        // ASSERT_NE): the coroutine-aware ASSERT_* macros (see
        // common/gtest_coro.h) expand to `co_return`, which would turn this
        // plain void method into a coroutine, so use the non-fatal variant and
        // guard the dereference with an explicit early return.
        EXPECT_NE(m_ssl_ctx.get(), nullptr) << "failed to load server SSL_CTX (test certificate material unavailable)";
        if (m_ssl_ctx == nullptr) {
            return;
        }
        SSL_CTX_set_alpn_select_cb(m_ssl_ctx.get(), detail::alpn_select_dot_cb, nullptr);

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
            tls_loop();
        });
    }

    // Stops the accept thread and closes the listening socket. Idempotent.
    // Mirrors LoopbackDnsServer::stop(): set running=false, shut down the
    // listening socket (unblocks accept()), join the thread, then release the
    // SSL_CTX. Because each connection is closed after one exchange, no
    // worker is ever left blocked on an SSL_read — deadlock-free shutdown.
    void stop() {
        if (!m_running.exchange(false)) {
            return;
        }
        detail::shutdown_socket(m_tcp_sock);
        detail::close_fd(m_tcp_sock);
        m_tcp_sock = detail::invalid_socket();
        if (m_thread.joinable()) {
            m_thread.join();
        }
        m_ssl_ctx.reset();
    }

    // "tls://127.0.0.1:<port>" — ready to use as an upstream address.
    std::string address() const {
        return AG_FMT("tls://127.0.0.1:{}", m_port);
    }

    uint16_t port() const {
        return m_port;
    }

private:
    // Single-threaded sequential accept loop (same deadlock-safety model as
    // LoopbackDnsServer::tcp_loop): one TLS exchange per accepted connection,
    // then close. For each connection: TLS handshake (SSL_accept), read the
    // 2-byte length prefix + payload, build the reply, write the 2-byte
    // length prefix + reply, then SSL_shutdown + close_fd.
    void tls_loop() {
        std::vector<uint8_t> buf;
        while (m_running.load()) {
            sockaddr_in client{};
            detail::socklen_type client_len = sizeof(client);
            detail::socket_type conn = ::accept(m_tcp_sock, reinterpret_cast<sockaddr *>(&client), &client_len);
            if (conn == detail::invalid_socket()) {
                break;
            }

            ag::UniquePtr<SSL, &SSL_free> ssl{SSL_new(m_ssl_ctx.get())};
            if (ssl == nullptr) {
                detail::close_fd(conn);
                continue;
            }
            SSL_set_fd(ssl.get(), static_cast<int>(conn));
            SSL_set_accept_state(ssl.get());
            if (SSL_accept(ssl.get()) <= 0) {
                detail::close_fd(conn);
                continue;
            }

            uint16_t len_net = 0;
            bool ok = detail::ssl_recv_exact(ssl.get(), reinterpret_cast<uint8_t *>(&len_net), 2);
            uint16_t msg_len = ok ? ntohs(len_net) : 0;
            if (!ok || msg_len == 0) {
                (void) SSL_shutdown(ssl.get());
                detail::close_fd(conn);
                continue;
            }
            buf.resize(msg_len);
            if (!detail::ssl_recv_exact(ssl.get(), buf.data(), msg_len)) {
                (void) SSL_shutdown(ssl.get());
                detail::close_fd(conn);
                continue;
            }

            auto reply = detail::build_dns_reply(m_handler, buf.data(), msg_len);
            if (reply) {
                uint16_t rlen_net = htons(static_cast<uint16_t>(reply->size()));
                (void) detail::ssl_send_exact(ssl.get(), reinterpret_cast<uint8_t *>(&rlen_net), 2);
                (void) detail::ssl_send_exact(ssl.get(), reply->data(), reply->size());
            }

            (void) SSL_shutdown(ssl.get());
            detail::close_fd(conn);
        }
    }

    Handler m_handler;
    uint16_t m_port{0};
    std::atomic_bool m_running{false};
    detail::socket_type m_tcp_sock{detail::invalid_socket()};
    ag::UniquePtr<SSL_CTX, &SSL_CTX_free> m_ssl_ctx;
    std::thread m_thread;
};

} // namespace ag::test
