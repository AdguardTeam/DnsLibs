#pragma once

// In-process HTTP CONNECT proxy bound to 127.0.0.1. It accepts a
// `CONNECT host:port HTTP/1.1` request, opens a plain TCP tunnel to the
// target, and relays bytes bidirectionally until either side closes. Used by
// the proxy-level outbound-proxy test (proxy/test/dnsproxy_test.cpp) so it
// stays fully offline: the DoT upstream performs TLS over the tunneled TCP
// connection to a local LoopbackTlsServer instead of a real public endpoint.
//
// CONNECT target limitation: the target host is interpreted as an IPv4 literal
// only (via inet_pton(AF_INET)). Hostname resolution (getaddrinfo) and IPv6
// literals are intentionally NOT supported: this helper exists solely to tunnel
// to an in-process loopback server addressed as 127.0.0.1:<port>, and
// performing DNS resolution would violate the default offline-only test
// policy. Non-IPv4-literal targets are rejected (the tunnel is closed) rather
// than resolved.
//
// Reuses the cross-platform socket helpers shared by LoopbackDnsServer
// (detail::open_stream_socket / close_fd / shutdown_socket / send_exact, etc.),
// so no new platform abstraction is introduced. The relay loop is
// single-threaded per connection and select()-driven with a short timeout so
// stop() (and shutdown of the active client sockets) unblocks it promptly.

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <gtest/gtest.h>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "common/net_utils.h"
#include "dns/common/dns_defs.h"

#include "loopback_dns_server.h" // detail:: socket helpers

namespace ag::test {

class LoopbackHttpConnectProxy {
public:
    LoopbackHttpConnectProxy() = default;

    ~LoopbackHttpConnectProxy() {
        stop();
    }

    LoopbackHttpConnectProxy(const LoopbackHttpConnectProxy &) = delete;
    LoopbackHttpConnectProxy &operator=(const LoopbackHttpConnectProxy &) = delete;

    // Binds 127.0.0.1:0, listens, starts the accept thread. Blocks until the
    // ephemeral port is assigned, so port() is usable on return.
    // Fail-fast: any socket()/bind()/listen() failure (or a port that resolves
    // to 0) records a test failure via ADD_FAILURE (not ASSERT_*: those expand to
    // `co_return` and would turn this void method into a coroutine), resets the
    // partially-opened socket, and returns without starting the accept thread or
    // flipping m_running — so stop()/destruction never join a non-existent
    // thread. Mirrors the defensive pattern in LoopbackTlsServer::start().
    void start() {
        if (m_running.load()) {
            return;
        }
        detail::ensure_winsock();
        m_listen_sock = detail::open_stream_socket();
        if (m_listen_sock == detail::invalid_socket()) {
            ADD_FAILURE() << "LoopbackHttpConnectProxy: socket() failed";
            return;
        }
        detail::set_reuseaddr(m_listen_sock);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(m_listen_sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
            ADD_FAILURE() << "LoopbackHttpConnectProxy: bind() failed";
            detail::close_fd(m_listen_sock);
            m_listen_sock = detail::invalid_socket();
            return;
        }
        m_port = detail::get_port(m_listen_sock);
        if (::listen(m_listen_sock, SOMAXCONN) != 0) {
            ADD_FAILURE() << "LoopbackHttpConnectProxy: listen() failed";
            detail::close_fd(m_listen_sock);
            m_listen_sock = detail::invalid_socket();
            m_port = 0;
            return;
        }
        if (m_port == 0) {
            ADD_FAILURE() << "LoopbackHttpConnectProxy: bound port resolved to 0";
            detail::close_fd(m_listen_sock);
            m_listen_sock = detail::invalid_socket();
            return;
        }
        m_running.store(true);
        m_thread = std::thread([this] {
            accept_loop();
        });
    }

    // Stops the accept thread, closes the listening socket, and shuts down any
    // active client sockets so their worker relays unblock via the select
    // timeout / peer reset and join promptly. Idempotent.
    void stop() {
        if (!m_running.exchange(false)) {
            return;
        }
        detail::shutdown_socket(m_listen_sock);
        detail::close_fd(m_listen_sock);
        m_listen_sock = detail::invalid_socket();
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            for (auto fd : m_active_client_fds) {
                detail::shutdown_socket(fd);
            }
        }
        if (m_thread.joinable()) {
            m_thread.join();
        }
        std::vector<std::thread> workers;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            workers.swap(m_workers);
        }
        for (auto &worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

    uint16_t port() const {
        return m_port;
    }

private:
    // Reads up to `max_bytes` until `delimiter` appears, appending to `out`.
    // Returns true if the delimiter was found.
    static bool read_until(detail::socket_type s, std::string &out, std::string_view delimiter, size_t max_bytes) {
        char buf[512];
        while (out.find(delimiter) == std::string::npos) {
            if (out.size() >= max_bytes) {
                return false;
            }
#ifdef _WIN32
            int n = ::recv(s, reinterpret_cast<char *>(buf), sizeof(buf), 0);
#else
            ssize_t n = ::recv(s, buf, sizeof(buf), 0);
#endif
            if (n <= 0) {
                return false;
            }
            out.append(buf, static_cast<size_t>(n));
        }
        return true;
    }

    // Parses the CONNECT target from the HTTP/1.1 request line and connects to
    // it over a plain TCP socket. Replies `200 Connection established`, then
    // relays bytes both ways until either side closes.
    void handle_connection(detail::socket_type client) {
        std::string req;
        if (!read_until(client, req, "\r\n\r\n", 8192)) {
            return;
        }
        // Expected form: "CONNECT host:port HTTP/1.1\r\n..."
        size_t sp1 = req.find(' ');
        if (sp1 == std::string::npos) {
            return;
        }
        size_t sp2 = req.find(' ', sp1 + 1);
        if (sp2 == std::string::npos) {
            return;
        }
        std::string target = req.substr(sp1 + 1, sp2 - sp1 - 1);
        size_t colon = target.rfind(':');
        if (colon == std::string::npos) {
            return;
        }
        std::string host = target.substr(0, colon);
        uint16_t target_port = 0;
        try {
            target_port = static_cast<uint16_t>(std::stoi(target.substr(colon + 1)));
        } catch (...) {
            return;
        }

        detail::socket_type target_sock = detail::open_stream_socket();
        if (target_sock == detail::invalid_socket()) {
            return;
        }
        sockaddr_in taddr{};
        taddr.sin_family = AF_INET;
        // IPv4-literal targets only: see the CONNECT target limitation note at
        // the top of this file. Hostnames/IPv6 are rejected (tunnel closed)
        // rather than resolved, keeping the helper network-free.
        if (inet_pton(AF_INET, host.c_str(), &taddr.sin_addr) != 1) {
            detail::close_fd(target_sock);
            return;
        }
        taddr.sin_port = htons(target_port);
        if (::connect(target_sock, reinterpret_cast<sockaddr *>(&taddr), sizeof(taddr)) != 0) {
            detail::close_fd(target_sock);
            return;
        }

        static constexpr std::string_view RESP = "HTTP/1.1 200 Connection established\r\n\r\n";
        if (!detail::send_exact(client, reinterpret_cast<const uint8_t *>(RESP.data()), RESP.size())) {
            detail::close_fd(target_sock);
            return;
        }

        relay(client, target_sock);
        detail::shutdown_socket(target_sock);
        detail::close_fd(target_sock);
    }

    // Single-threaded bidirectional relay using select() with a short timeout so
    // the loop re-checks m_running even when both peers are idle. Exits on EOF,
    // socket error, or stop(). Shuts down both sockets on exit so the peer
    // (DoT client / TLS server) observes the tunnel closing promptly.
    void relay(detail::socket_type a, detail::socket_type b) {
        uint8_t buf[4096];
        while (m_running.load()) {
            fd_set set;
            FD_ZERO(&set);
            FD_SET(a, &set);
            FD_SET(b, &set);
            timeval tv{};
            tv.tv_sec = 0;
            tv.tv_usec = 100 * 1000; // 100 ms
            int nfds = (a > b ? a : b) + 1;
            int r = ::select(nfds, &set, nullptr, nullptr, &tv);
            if (r < 0) {
                break;
            }
            if (r == 0) {
                continue; // timeout: re-check m_running
            }
            if (FD_ISSET(a, &set)) {
#ifdef _WIN32
                int n = ::recv(a, reinterpret_cast<char *>(buf), sizeof(buf), 0);
#else
                ssize_t n = ::recv(a, buf, sizeof(buf), 0);
#endif
                if (n <= 0) {
                    break;
                }
                if (!detail::send_exact(b, buf, static_cast<size_t>(n))) {
                    break;
                }
            }
            if (FD_ISSET(b, &set)) {
#ifdef _WIN32
                int n = ::recv(b, reinterpret_cast<char *>(buf), sizeof(buf), 0);
#else
                ssize_t n = ::recv(b, buf, sizeof(buf), 0);
#endif
                if (n <= 0) {
                    break;
                }
                if (!detail::send_exact(a, buf, static_cast<size_t>(n))) {
                    break;
                }
            }
        }
        detail::shutdown_socket(a);
        detail::shutdown_socket(b);
    }

    void accept_loop() {
        while (m_running.load()) {
            sockaddr_in client{};
            detail::socklen_type client_len = sizeof(client);
            detail::socket_type conn = ::accept(m_listen_sock, reinterpret_cast<sockaddr *>(&client), &client_len);
            if (conn == detail::invalid_socket()) {
                break;
            }
            std::thread worker([this, conn] {
                handle_connection(conn);
                std::lock_guard<std::mutex> lk(m_mutex);
                m_active_client_fds.erase(std::remove(m_active_client_fds.begin(), m_active_client_fds.end(), conn),
                        m_active_client_fds.end());
                detail::close_fd(conn);
            });
            {
                std::lock_guard<std::mutex> lk(m_mutex);
                m_active_client_fds.push_back(conn);
                m_workers.push_back(std::move(worker));
            }
        }
    }

    uint16_t m_port{0};
    std::atomic_bool m_running{false};
    detail::socket_type m_listen_sock{detail::invalid_socket()};
    std::thread m_thread;
    std::mutex m_mutex;
    std::vector<detail::socket_type> m_active_client_fds;
    std::vector<std::thread> m_workers;
};

} // namespace ag::test
