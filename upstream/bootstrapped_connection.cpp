#include "bootstrapped_connection.h"

#include <cassert>
#include <optional>
#include <utility>
#include <vector>

#include <fmt/std.h>

#include "common/logger.h"
#include "common/parallel.h"
#include "common/socket_address.h"
#include "dns/net/socket.h"

#define log_conn(l_, lvl_, conn_, fmt_, ...)                                                                           \
    lvl_##log(l_, "[id={} addr={}] " fmt_, conn_->m_id, conn_->address_str(), ##__VA_ARGS__)

namespace ag::dns {

void BootstrappedFramedConnection::connect() {
    assert(m_state == Connection::Status::IDLE);
    m_state = Connection::Status::PENDING;
    coro::run_detached(this->co_connect());
}

void BootstrappedFramedConnection::finish_request(uint16_t request_id, Reply &&reply) {
    if (reply.has_error()) {
        if (auto error = reply.error()->value(); error == DnsError::AE_SOCKET_ERROR || error == DnsError::AE_TIMED_OUT
                || error == DnsError::AE_CONNECTION_CLOSED) {
            if (auto pool = m_pool.lock()) {
                if (auto upstream = pool->upstream(); upstream && bootstrapper(upstream)) {
                    if (const auto *saddr = std::get_if<SocketAddress>(&m_address)) {
                        bootstrapper(upstream)->remove_resolved(*saddr);
                    }
                }
            }
        }
    }
    this->DnsFramedConnection::finish_request(request_id, std::move(reply));
}

coro::Task<void> BootstrappedFramedConnection::co_connect() {
    auto pool = m_pool.lock();
    assert(pool != nullptr);
    // The upstream owns the bootstrapper, keep it alive for the whole connect.
    auto upstream = pool->upstream();
    assert(upstream != nullptr);

    Bootstrapper *bs = bootstrapper(upstream);
    const Millis timeout = upstream->config().timeout;

    std::vector<SocketAddress> candidates;
    if (bs != nullptr) {
        auto weak_self = weak_from_this();
        auto result = co_await bs->get();
        if (weak_self.expired()) {
            co_return;
        }
        if (result.error) {
            auto &err = *result.error;
            log_conn(m_log, err, this, "Failed to bootstrap: {}", err.str());
            this->on_close(make_error(DnsError::AE_BOOTSTRAP_ERROR, result.error));
            co_return;
        }
        if (result.addresses.empty()) {
            log_conn(m_log, warn, this, "Bootstrapper returned an empty address list");
            this->on_close(make_error(DnsError::AE_BOOTSTRAP_ERROR, "Bootstrapper returned an empty address list"));
            co_return;
        }

        // Race one IPv4 and one IPv6 candidate.
        bool found_ipv4 = false;
        bool found_ipv6 = false;
        for (const auto &addr : result.addresses) {
            if (found_ipv4 && found_ipv6) {
                break;
            }
            if (addr.is_ipv4() && !std::exchange(found_ipv4, true)) {
                candidates.push_back(addr);
            } else if (addr.is_ipv6() && !std::exchange(found_ipv6, true)) {
                candidates.push_back(addr);
            }
        }
    }

    if (!candidates.empty()) {
        struct ConnectAttempt {
            SocketAddress address;
            SocketFactory::SocketPtr stream;
            std::optional<Error<SocketError>> result;
            std::coroutine_handle<> handle;

            void complete_with(Error<SocketError> error) {
                if (result.has_value()) {
                    return;
                }

                result = error;
                auto h = handle;
                if (h) {
                    handle = nullptr;
                    h();
                }
            }

            void cancel() {
                complete_with(make_error(SocketError::AE_CONNECTION_REFUSED));
                stream.reset();
            }

            coro::Task<Result<SocketAddress, DnsError>> try_connect(BootstrappedFramedConnection *conn,
                    const std::shared_ptr<Upstream> &upstream, EventLoop *loop, Millis timeout) {
                stream = conn->make_stream(upstream);

                auto on_connected = [](void *arg) {
                    auto *self = static_cast<ConnectAttempt *>(arg);
                    self->complete_with(Error<SocketError>());
                };

                auto on_close = [](void *arg, Error<SocketError> error) {
                    auto *self = static_cast<ConnectAttempt *>(arg);
                    self->complete_with(error ? error : make_error(SocketError::AE_CONNECTION_REFUSED));
                };

                auto err = stream->connect({
                        loop,
                        address,
                        {on_connected, nullptr, on_close, this},
                        timeout,
                });

                if (err) {
                    // Record the failure so the caller can evict this address
                    // from the bootstrap cache even when connect() failed
                    // synchronously (no on_close fires).
                    this->complete_with(err);
                    co_return make_error(DnsError::AE_SOCKET_ERROR, err);
                }

                struct Awaitable {
                    ConnectAttempt *self;
                    bool await_ready() {
                        return self->result.has_value();
                    }
                    bool await_suspend(std::coroutine_handle<> h) {
                        self->handle = h;
                        // Check again after setting handle to avoid race
                        return !self->result.has_value();
                    }
                    Result<SocketAddress, DnsError> await_resume() {
                        self->handle = nullptr;
                        if (!self->result.has_value()) {
                            return make_error(DnsError::AE_SHUTTING_DOWN);
                        }
                        if (self->result.value()) {
                            return make_error(DnsError::AE_SOCKET_ERROR, self->result.value());
                        }
                        return self->address;
                    }
                };
                co_return co_await Awaitable{.self = this};
            }
        };

        std::vector<ConnectAttempt> attempts;
        attempts.reserve(candidates.size());
        for (const auto &addr : candidates) {
            attempts.emplace_back(addr);
        }

        auto op = parallel::any_of_cond<Result<SocketAddress, DnsError>>(
                [](const Result<SocketAddress, DnsError> &result) {
                    return !result.has_error();
                });
        for (auto &attempt : attempts) {
            op.add(attempt.try_connect(this, upstream, &m_loop, timeout));
        }

        auto cancel_all = [&attempts]() {
            for (auto &attempt : attempts) {
                attempt.cancel();
            }
        };

        auto weak_self = weak_from_this();
        std::optional<Result<SocketAddress, DnsError>> winner = co_await op;
        if (weak_self.expired()) {
            cancel_all();
            co_return;
        }

        // Remove failed addresses from the bootstrap cache.
        // Note: If the attempt.try_connect() coroutine hasn't finished yet,
        // we won't remove its address, even if it later fails.
        if (bs != nullptr) {
            for (auto &attempt : attempts) {
                if (attempt.result.has_value() && attempt.result.value()) {
                    bs->remove_resolved(attempt.address);
                }
            }
        }

        if (!winner.has_value() || winner->has_error()) {
            cancel_all();
            Error<DnsError> final_error = winner.has_value()
                    ? winner->error()
                    : make_error(DnsError::AE_SOCKET_ERROR, "All connection attempts failed");
            log_conn(m_log, dbg, this, "Failed to connect to any address: {}", final_error->str());
            this->on_close(final_error);
            co_return;
        }

        SocketAddress winner_addr = winner->value();
        for (auto &attempt : attempts) {
            if (attempt.address == winner_addr) {
                if (attempt.result.has_value() && !attempt.result.value()) {
                    m_stream = std::move(attempt.stream);
                    m_address = winner_addr;
                }
            } else {
                attempt.cancel();
            }
        }

        if (!m_stream) {
            cancel_all();
            log_conn(m_log, dbg, this, "Internal error: winner stream not found");
            this->on_close(make_error(DnsError::AE_SOCKET_ERROR, "Internal error"));
            co_return;
        }

        auto err = m_stream->set_callbacks({on_connected, on_read, on_close, this});
        if (err) {
            log_conn(m_log, dbg, this, "Failed to set callbacks: {}", err->str());
            on_close(this, err);
            co_return;
        }

        on_connected(this);
    } else {
        m_address = no_bootstrap_address(upstream);
        m_stream = make_stream(upstream);
        dbglog(m_log, "{}", m_address);
        auto err = m_stream->connect({
                &m_loop,
                m_address,
                {on_connected, on_read, on_close, this},
                timeout,
        });
        if (err) {
            log_conn(m_log, err, this, "Failed to start connect: {}", err->str());
            on_close(this, err);
        }
    }
}

} // namespace ag::dns
