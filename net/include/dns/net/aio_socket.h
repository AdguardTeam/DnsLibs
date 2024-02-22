#pragma once

#include <functional>

#include "common/coro.h"
#include "common/logger.h"
#include "dns/common/dns_defs.h"
#include "dns/common/event_loop.h"
#include "dns/net/socket.h"

namespace ag::dns {

class AioSocket {
public:
    struct OnReadCallback {
        /**
         * Raised after a data chunk has been received.
         * The caller should accumulate the data itself.
         * @return true if reading must go on, false otherwise
         */
        bool (* func)(void *arg, Uint8View data);
        /** User context for the callbacks */
        void *arg;
    };

    struct ConnectParameters {
        /** Event loop for operation */
        EventLoop *loop = nullptr;
        /** Address on the peer to connect to */
        const AddressVariant &peer;
        /** Operation time out value */
        std::optional<Micros> timeout;
    };

    explicit AioSocket(SocketFactory::SocketPtr socket);
    ~AioSocket();

    /**
     * Connect to the peer
     * @param params connect parameters
     * @return some error if failed
     */
    template <typename Ret = Error<SocketError>>
    [[nodiscard]] auto connect(ConnectParameters params) {
        struct Awaitable {
            Ret result;
            ConnectParameters params;
            AioSocket *self;
            bool await_ready() { return false; }
            void await_suspend(std::coroutine_handle<> h) {
                self->connect(params, [this, h](Ret error) mutable {
                    result = std::move(error);
                    h.resume();
                });
            }
            Ret await_resume() { return result; }
        };
        return Awaitable{.params = params, .self = this};
    }

    /**
     * Send data to the peer
     * @param data the data
     * @return some error if failed
     */
    [[nodiscard]] Error<SocketError> send(Uint8View data);

    /**
     * Receive data from the peer.
     * Blocks until either an error happened or interrupted via `on_read_callback` by the caller.
     * @param on_read_handler read events handler
     * @param timeout operation timeout
     * @return some error if failed
     */
    template <typename Ret = Error<SocketError>>
    [[nodiscard]] auto receive(OnReadCallback on_read_handler, std::optional<Micros> timeout) {
        struct Awaitable {
            Ret result;
            OnReadCallback on_read_handler;
            std::optional<Micros> timeout;
            AioSocket *self;
            bool await_ready() { return false; }
            void await_suspend(std::coroutine_handle<> h) {
                self->receive(on_read_handler, timeout, [this, h](Ret error) mutable {
                    result = std::move(error);
                    h.resume();
                });
            }
            Ret await_resume() { return result; }
        };
        return Awaitable{.on_read_handler = on_read_handler, .timeout = timeout, .self = this};
    }

    /**
     * Get the underlying socket implementation
     */
    [[nodiscard]] Socket *get_underlying() const;

private:
    Logger m_log;
    size_t m_id = 0;
    SocketFactory::SocketPtr m_underlying_socket;
    OnReadCallback m_on_read_callback = {};
    Error<SocketError> m_pending_error;

    [[nodiscard]] Socket::ConnectParameters make_underlying_connect_parameters(
            ConnectParameters &params) const;
    [[nodiscard]] Socket::Callbacks make_callbacks(bool want_read) const;
    static void on_connected(void *arg);
    static void on_read(void *arg, Uint8View data);
    static void on_close(void *arg, Error<SocketError> error);

    std::function<void(Error<SocketError>)> m_handler;
    void connect(ConnectParameters params, std::function<void(Error<SocketError>)> handler);
    void receive(OnReadCallback on_read_handler, std::optional<Micros> timeout, std::function<void(Error<SocketError>)> handler);
};

}
