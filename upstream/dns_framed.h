#pragma once

#include <mutex>
#include <list>
#include <condition_variable>
#include <event2/event.h>
#include <event2/bufferevent.h>

#include "common/logger.h"
#include "common/parallel.h"
#include "dns/common/event_loop.h"
#include "dns/net/tcp_dns_buffer.h"
#include "dns/net/tls_session_cache.h"
#include "dns/upstream/upstream.h"

#include "connection.h"

namespace ag::dns {

class DnsFramedConnection;

using DnsFramedConnectionPtr = std::shared_ptr<DnsFramedConnection>;

/**
 * DNS framed connection class.
 * It uses format specified in DNS RFC for TCP connections:
 * - Header is 2 bytes - length of payload
 * - Payload is DNS packet content as sent by UDP
 *
 * Note that this class is extendable (for DoT) but already inherited from `enable_shared_from_this`.
 */
class DnsFramedConnection : public Connection, public std::enable_shared_from_this<DnsFramedConnection> {
public:
    DnsFramedConnection(const ConstructorAccess &access, EventLoop &loop, const ConnectionPoolPtr &pool,
            const std::string &address_str);
    static DnsFramedConnectionPtr create(
            EventLoop &loop, const ConnectionPoolPtr &pool, const std::string &address_str) {
        return std::make_shared<DnsFramedConnection>(ConstructorAccess{}, loop, pool, address_str);
    }
    virtual void connect();

    ~DnsFramedConnection() override;

    /** Logger */
    Logger m_log;
    /** Connection id */
    uint32_t m_id{};
    /** Address */
    SocketAddress m_address;
    /** Input buffer */
    TcpDnsBuffer m_input_buffer;
    /** Connection handle */
    SocketFactory::SocketPtr m_stream;
    /** Idle timeout */
    std::chrono::milliseconds m_idle_timeout{};
    /** Map of requests */
    HashMap<int, Request *> m_requests;
    /** Next request id */
    static std::atomic<uint16_t> m_next_request_id;
    coro::Task<Reply> perform_request(Uint8View packet, Millis timeout) override;
    virtual void resume_request(uint16_t request_id);
    virtual void finish_request(uint16_t request_id, Reply &&reply);

    static void on_connected(void *arg);
    static void on_read(void *arg, Uint8View data);
    static void on_close(void *arg, Error<SocketError> error);
    void on_close(Error<DnsError> dns_error);
    std::string address_str() {
        if (m_address.valid()) {
            return AG_FMT("{}({})", m_address_str, m_address.str());
        } else {
            return AG_FMT("{}()", m_address_str);
        }
    }

    auto ensure_connected(Request *request) {
        struct Awaitable {
            DnsFramedConnection *self;
            Request *req;
            bool await_ready() {
                if (self->m_state == Connection::Status::CLOSED) {
                    req->reply = Reply(make_error(DE_CONNECTION_CLOSED));
                    return true;
                }
                return self->m_state == Connection::Status::ACTIVE;
            }
            void await_suspend(std::coroutine_handle<> h) {
                self->m_requests[req->request_id] = req;
                req->caller = h;
                if (self->m_state == Connection::Status::IDLE) {
                    self->connect();
                }
            }
            void await_resume() {}
        };
        auto wait_timeout = [](EventLoop &loop, std::weak_ptr<DnsFramedConnection> conn, Millis timeout, uint16_t request_id) -> coro::Task<void> {
            co_await loop.co_sleep(timeout);
            if (DnsFramedConnection *self = conn.lock().get()) {
                self->finish_request(request_id, Reply{make_error(DE_TIMED_OUT)});
            }
        };
        return parallel::any_of_void(
                Awaitable{.self = this, .req = request},
                wait_timeout(m_loop, weak_from_this(), request->timeout, request->request_id)
        );
    }

    auto wait_response(Request *request) {
        struct Awaitable {
            DnsFramedConnection *self;
            Request *req;
            bool await_ready() {
                return false;
            }
            void await_suspend(std::coroutine_handle<> h) {
                dbglog(self->m_log, "Waiting response...");
                self->m_requests[req->request_id] = req;
                req->caller = h;
            }
            void await_resume() {}
        };
        auto wait_timeout = [](EventLoop &loop, std::weak_ptr<DnsFramedConnection> conn, Millis timeout, uint16_t request_id) -> coro::Task<void> {
            co_await loop.co_sleep(timeout);
            if (DnsFramedConnection *self = conn.lock().get()) {
                self->finish_request(request_id, Reply{make_error(DE_TIMED_OUT)});
            }
        };
        return parallel::any_of_void(
                Awaitable{.self = this, .req = request},
                wait_timeout(m_loop, weak_from_this(), request->timeout, request->request_id)
        );
    }
};

} // namespace ag::dns