#pragma once

// In-process DNS responder bound to 127.0.0.1. It never performs real network
// I/O: UDP and TCP listeners share one ephemeral loopback port and reply with
// canned responses built by a user-supplied handler. Intended as a test double
// for upstream/protocol tests that should not depend on the public internet.

#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <ldns/ldns.h>

#include "common/net_utils.h"
#include "dns/common/dns_defs.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace ag::test::detail {

#ifdef _WIN32
using socket_type = SOCKET;
#else
using socket_type = int;
#endif

// Returns the platform's "invalid socket" sentinel.
inline socket_type invalid_socket() {
#ifdef _WIN32
    return INVALID_SOCKET;
#else
    return static_cast<socket_type>(-1);
#endif
}

// Initializes Winsock once per process (no-op on POSIX).
inline void ensure_winsock() {
#ifdef _WIN32
    static struct WsaInit {
        WsaInit() {
            WSADATA data{};
            (void) ::WSAStartup(MAKEWORD(2, 2), &data);
        }
        ~WsaInit() {
            (void) ::WSACleanup();
        }
    } init;
    (void) init;
#endif
}

inline socket_type open_dgram_socket() {
    return ::socket(AF_INET, SOCK_DGRAM, 0);
}

inline socket_type open_stream_socket() {
    return ::socket(AF_INET, SOCK_STREAM, 0);
}

#ifdef _WIN32
using socklen_type = int;
#else
using socklen_type = socklen_t;
#endif

// Reads the locally bound port of `s`, or 0 if it is not bound.
inline uint16_t get_port(socket_type s) {
    sockaddr_in addr{};
    socklen_type len = sizeof(addr);
    if (::getsockname(s, reinterpret_cast<sockaddr *>(&addr), &len) != 0) {
        return 0;
    }
    return ntohs(addr.sin_port);
}

inline void set_reuseaddr(socket_type s) {
    int opt = 1;
    (void) ::setsockopt(
            s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&opt), static_cast<socklen_type>(sizeof(opt)));
}

// Named close_fd (not close_socket) because ldns defines close_socket as a
// macro, which would macro-expand the function name at its declaration.
inline void close_fd(socket_type s) {
    if (s != invalid_socket()) {
#ifdef _WIN32
        (void) ::closesocket(s);
#else
        (void) ::close(s);
#endif
    }
}

inline void shutdown_socket(socket_type s) {
    if (s != invalid_socket()) {
#ifdef _WIN32
        (void) ::shutdown(s, SD_BOTH);
#else
        (void) ::shutdown(s, SHUT_RDWR);
#endif
    }
}

// Maximum DNS packet size (RFC 1035 / framing limits). Shared by the
// loopback plain DNS and TLS servers for their receive/encode buffers.
inline constexpr size_t MAX_DNS_PACKET = 65535;

// Handler invoked for each accepted DNS request: receives the parsed query
// packet and returns a reply packet (or an empty pointer to drop the query,
// e.g. for timeout/negative tests). Shared by the loopback plain DNS and TLS
// servers so both use the same `build_dns_reply` wire-encode path.
using DnsReplyHandler = std::function<ag::dns::ldns_pkt_ptr(const ldns_pkt &)>;

// Parses `req_len` wire bytes into a packet, invokes `handler`, and encodes
// the reply back to wire bytes. Returns nullopt to drop the query (e.g. for
// timeout/negative tests). Extracted from LoopbackDnsServer so that
// LoopbackTlsServer can reuse the same parse → handler → serialize path.
inline std::optional<std::vector<uint8_t>> build_dns_reply(
        const DnsReplyHandler &handler, const uint8_t *req_data, size_t req_len) {
    if (!handler) {
        return std::nullopt;
    }
    ldns_pkt *request_raw = nullptr;
    ldns_status st = ldns_wire2pkt(&request_raw, req_data, req_len);
    ag::dns::ldns_pkt_ptr request{request_raw};
    if (st != LDNS_STATUS_OK || !request) {
        return std::nullopt;
    }
    ag::dns::ldns_pkt_ptr reply = handler(*request);
    if (!reply) {
        return std::nullopt;
    }
    ag::dns::ldns_buffer_ptr buffer{ldns_buffer_new(MAX_DNS_PACKET)};
    if (!buffer) {
        return std::nullopt;
    }
    if (ldns_pkt2buffer_wire(buffer.get(), reply.get()) != LDNS_STATUS_OK) {
        return std::nullopt;
    }
    const uint8_t *data = ldns_buffer_begin(buffer.get());
    size_t size = ldns_buffer_position(buffer.get());
    return std::vector<uint8_t>(data, data + size);
}

// Receives exactly `len` bytes. Returns false on EOF/error.
inline bool recv_exact(socket_type s, uint8_t *dst, size_t len) {
    while (len > 0) {
#ifdef _WIN32
        int n = ::recv(s, reinterpret_cast<char *>(dst), static_cast<int>(len), 0);
#else
        ssize_t n = ::recv(s, dst, len, 0);
#endif
        if (n <= 0) {
            return false;
        }
        dst += static_cast<size_t>(n);
        len -= static_cast<size_t>(n);
    }
    return true;
}

// Sends exactly `len` bytes. Returns false on error.
inline bool send_exact(socket_type s, const uint8_t *src, size_t len) {
    while (len > 0) {
#ifdef _WIN32
        int n = ::send(s, reinterpret_cast<const char *>(src), static_cast<int>(len), 0);
#else
        ssize_t n = ::send(s, src, len, 0);
#endif
        if (n <= 0) {
            return false;
        }
        src += static_cast<size_t>(n);
        len -= static_cast<size_t>(n);
    }
    return true;
}

} // namespace ag::test::detail

namespace ag::test {

class LoopbackDnsServer {
public:
    // Returns an ldns reply packet for the given parsed request, or an empty
    // pointer to drop the query (e.g. for timeout/negative tests).
    using Handler = detail::DnsReplyHandler;

    explicit LoopbackDnsServer(Handler handler, bool tcp = true, bool udp = true)
            : m_handler(std::move(handler))
            , m_tcp(tcp)
            , m_udp(udp) {
    }

    ~LoopbackDnsServer() {
        stop();
    }

    LoopbackDnsServer(const LoopbackDnsServer &) = delete;
    LoopbackDnsServer &operator=(const LoopbackDnsServer &) = delete;

    // Binds 127.0.0.1:0, starts the worker thread(s). Blocks until the
    // ephemeral port is assigned, so address()/port() are usable on return.
    //
    // The UDP and TCP listeners must share one ephemeral port: start() asks the
    // OS for a port by binding UDP to :0, then binds TCP to that same port. A
    // concurrent test server (or a lingering TIME_WAIT socket) can grab the TCP
    // port in the gap between the two binds, making the TCP bind() fail with
    // EADDRINUSE. Instead of failing the test outright, start() re-rolls the
    // ephemeral port a bounded number of times — this is the exact flake
    // documented in proxy/test/listener_test.cpp (the "many pending" storm is
    // capped at 1 000 to avoid exhausting the ephemeral range), and the retry
    // makes the bind structurally immune to it.
    //
    // Fail-fast still applies to non-retryable failures (socket()/UDP bind()
    // failed — system-level resource exhaustion no port re-roll can fix): these
    // record a test failure via ADD_FAILURE (not ASSERT_*: those expand to
    // `co_return` and would turn this void method into a coroutine), reset the
    // partially-opened sockets, and return without starting any worker thread
    // or flipping m_running — so stop()/destruction never join a non-existent
    // thread. Mirrors the defensive pattern in LoopbackTlsServer::start(), with
    // the added retry for the racy two-transport shared-port bind.
    static constexpr int MAX_BIND_ATTEMPTS = 16;

    void start() {
        if (m_running.load()) {
            return;
        }
        detail::ensure_winsock();

        for (int attempt = 0; attempt < MAX_BIND_ATTEMPTS; ++attempt) {
            BindAttempt result = bind_once();
            if (result == BindAttempt::SUCCESS) {
                // All socket setup succeeded: flip m_running and start the
                // worker thread(s) only now, so a setup failure never leaves
                // the server running on an invalid/unbound socket (and never
                // leaves one transport running while the other failed).
                m_running.store(true);
                if (m_udp) {
                    m_udp_thread = std::thread([this] {
                        udp_loop();
                    });
                }
                if (m_tcp) {
                    m_tcp_thread = std::thread([this] {
                        tcp_loop();
                    });
                }
                return;
            }
            // Close the partially-opened sockets (and clear m_port) before
            // either retrying with a fresh ephemeral port or returning.
            reset_start_state();
            if (result == BindAttempt::FATAL) {
                // bind_once() already recorded the reason via ADD_FAILURE.
                return;
            }
            // RETRY: the TCP port lost an ephemeral-port race — re-roll and
            // try again.
        }
        ADD_FAILURE() << "LoopbackDnsServer: bind() failed after " << MAX_BIND_ATTEMPTS << " attempts";
    }

    // Stops the worker thread(s) and closes the socket(s). Idempotent.
    void stop() {
        if (!m_running.exchange(false)) {
            return;
        }
        detail::shutdown_socket(m_udp_sock);
        detail::shutdown_socket(m_tcp_sock);
        detail::close_fd(m_udp_sock);
        detail::close_fd(m_tcp_sock);
        m_udp_sock = detail::invalid_socket();
        m_tcp_sock = detail::invalid_socket();
        if (m_udp_thread.joinable()) {
            m_udp_thread.join();
        }
        if (m_tcp_thread.joinable()) {
            m_tcp_thread.join();
        }
    }

    // "<scheme>://127.0.0.1:<port>" — ready to use as an upstream address.
    std::string address(ag::utils::TransportProtocol proto) const {
        const char *scheme = (proto == ag::utils::TP_TCP) ? "tcp" : "udp";
        return AG_FMT("{}://127.0.0.1:{}", scheme, m_port);
    }

    uint16_t port() const {
        return m_port;
    }

private:
    // Delegates to the shared detail::build_dns_reply helper so that the
    // parse → handler → serialize path is identical to LoopbackTlsServer.
    std::optional<std::vector<uint8_t>> build_reply_raw(const uint8_t *req_data, size_t req_len) {
        return detail::build_dns_reply(m_handler, req_data, req_len);
    }

    // Outcome of one bind attempt in start(). SUCCESS means both transports are
    // bound and m_port is usable; RETRY means the TCP side lost an
    // ephemeral-port race (close + re-roll the port); FATAL means a
    // non-retryable socket()/UDP-bind() failure (ADD_FAILURE already recorded).
    enum class BindAttempt {
        SUCCESS,
        RETRY,
        FATAL,
    };

    // One bind attempt for the configured transports. Shares one ephemeral
    // port between UDP and TCP: binds UDP to :0 (the OS assigns P), then binds
    // TCP to P. Returns SUCCESS when both listeners are bound and m_port is
    // non-zero; RETRY when the TCP bind() to P collided with a concurrent test
    // server / lingering socket (start() then re-rolls P); FATAL on a
    // non-retryable failure (recorded via ADD_FAILURE for the same
    // coroutine-safety reason documented on start()).
    BindAttempt bind_once() {
        if (m_udp) {
            m_udp_sock = detail::open_dgram_socket();
            if (m_udp_sock == detail::invalid_socket()) {
                ADD_FAILURE() << "LoopbackDnsServer: UDP socket() failed";
                return BindAttempt::FATAL;
            }
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = 0;
            if (::bind(m_udp_sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
                ADD_FAILURE() << "LoopbackDnsServer: UDP bind() failed";
                return BindAttempt::FATAL;
            }
            m_port = detail::get_port(m_udp_sock);
            if (m_port == 0) {
                ADD_FAILURE() << "LoopbackDnsServer: UDP bound port resolved to 0";
                return BindAttempt::FATAL;
            }
        }

        if (m_tcp) {
            m_tcp_sock = detail::open_stream_socket();
            if (m_tcp_sock == detail::invalid_socket()) {
                ADD_FAILURE() << "LoopbackDnsServer: TCP socket() failed";
                return BindAttempt::FATAL;
            }
            detail::set_reuseaddr(m_tcp_sock);
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(m_port);
            if (::bind(m_tcp_sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
                // The TCP port lost a race with a concurrent test server or a
                // lingering TIME_WAIT socket. Re-roll the ephemeral port
                // (start() closes the partial sockets and loops). The "TCP
                // bind() failed" reason surfaces only if every attempt loses
                // the race.
                return BindAttempt::RETRY;
            }
            if (m_port == 0) {
                m_port = detail::get_port(m_tcp_sock);
            }
            if (::listen(m_tcp_sock, SOMAXCONN) != 0) {
                ADD_FAILURE() << "LoopbackDnsServer: TCP listen() failed";
                return BindAttempt::FATAL;
            }
            if (m_port == 0) {
                ADD_FAILURE() << "LoopbackDnsServer: TCP bound port resolved to 0";
                return BindAttempt::FATAL;
            }
        }

        return BindAttempt::SUCCESS;
    }

    // Closes any sockets opened by start() and resets port bookkeeping. Used
    // only by start()'s fail-fast / retry branches so the server is never left
    // half-initialized (one transport up, the other down). Idempotent: closing
    // an invalid_socket() is a no-op.
    void reset_start_state() {
        detail::close_fd(m_udp_sock);
        detail::close_fd(m_tcp_sock);
        m_udp_sock = detail::invalid_socket();
        m_tcp_sock = detail::invalid_socket();
        m_port = 0;
    }

    void udp_loop() {
        std::vector<uint8_t> buf(detail::MAX_DNS_PACKET);
        while (m_running.load()) {
            sockaddr_in client{};
            detail::socklen_type client_len = sizeof(client);
#ifdef _WIN32
            int n = ::recvfrom(m_udp_sock, reinterpret_cast<char *>(buf.data()), static_cast<int>(buf.size()), 0,
                    reinterpret_cast<sockaddr *>(&client), &client_len);
#else
            ssize_t n = ::recvfrom(
                    m_udp_sock, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr *>(&client), &client_len);
#endif
            if (n <= 0) {
                break;
            }
            auto reply = build_reply_raw(buf.data(), static_cast<size_t>(n));
            if (reply) {
#ifdef _WIN32
                (void) ::sendto(m_udp_sock, reinterpret_cast<const char *>(reply->data()),
                        static_cast<int>(reply->size()), 0, reinterpret_cast<sockaddr *>(&client), client_len);
#else
                (void) ::sendto(
                        m_udp_sock, reply->data(), reply->size(), 0, reinterpret_cast<sockaddr *>(&client), client_len);
#endif
            }
        }
    }

    // One query per accepted connection: read a 2-byte length prefix, the
    // payload, build the reply, write it back length-prefixed, then close.
    // Closing after each reply keeps stop() deadlock-free (no worker is ever
    // left blocked on a connection's recv()).
    void tcp_loop() {
        std::vector<uint8_t> buf;
        while (m_running.load()) {
            sockaddr_in client{};
            detail::socklen_type client_len = sizeof(client);
            detail::socket_type conn = ::accept(m_tcp_sock, reinterpret_cast<sockaddr *>(&client), &client_len);
            if (conn == detail::invalid_socket()) {
                break;
            }
            uint16_t len_net = 0;
            bool ok = detail::recv_exact(conn, reinterpret_cast<uint8_t *>(&len_net), 2);
            uint16_t msg_len = ok ? ntohs(len_net) : 0;
            if (!ok || msg_len == 0) {
                detail::close_fd(conn);
                continue;
            }
            buf.resize(msg_len);
            if (!detail::recv_exact(conn, buf.data(), msg_len)) {
                detail::close_fd(conn);
                continue;
            }
            auto reply = build_reply_raw(buf.data(), msg_len);
            if (reply) {
                uint16_t rlen_net = htons(static_cast<uint16_t>(reply->size()));
                (void) detail::send_exact(conn, reinterpret_cast<uint8_t *>(&rlen_net), 2);
                (void) detail::send_exact(conn, reply->data(), reply->size());
            }
            detail::close_fd(conn);
        }
    }

    Handler m_handler;
    bool m_tcp;
    bool m_udp;
    uint16_t m_port{0};
    std::atomic_bool m_running{false};
    detail::socket_type m_udp_sock{detail::invalid_socket()};
    detail::socket_type m_tcp_sock{detail::invalid_socket()};
    std::thread m_udp_thread;
    std::thread m_tcp_thread;
};

} // namespace ag::test
