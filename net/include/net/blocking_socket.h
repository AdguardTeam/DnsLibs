#pragma once


#include "socket.h"
#include "common/event_loop.h"
#include "common/logger.h"


namespace ag {

class BlockingSocket {
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
        /** Address on the peer to connect to */
        const SocketAddress &peer;
        /** Operation time out value */
        std::optional<Micros> timeout;
    };

    using ReceiveDnsPacketResult = std::variant<
            /** A DNS packet if successful */
            Uint8Vector,
            /** An error if failed */
            Socket::Error>;

    explicit BlockingSocket(SocketFactory::SocketPtr socket);
    ~BlockingSocket();

    /**
     * Connect to the peer
     * @param params connect parameters
     * @return some error if failed
     */
    [[nodiscard]] std::optional<Socket::Error> connect(ConnectParameters params);

    /**
     * Send data to the peer
     * @param data the data
     * @return some error if failed
     */
    [[nodiscard]] std::optional<Socket::Error> send(Uint8View data);

    /**
     * Send DNS packet to the peer
     * @param data the packet
     * @return some error if failed
     */
    [[nodiscard]] std::optional<Socket::Error> send_dns_packet(Uint8View data);

    /**
     * Receive data from the peer.
     * Blocks until either an error happened or interrupted via `on_read_callback` by the caller.
     * @param on_read_handler read events handler
     * @param timeout operation timeout
     * @return some error if failed
     */
    [[nodiscard]] std::optional<Socket::Error> receive(OnReadCallback on_read_handler,
                                                       std::optional<Micros> timeout);

    /**
     * Receive DNS packet from the peer.
     * Blocks until either an error happened or the packet is fully received.
     * @param timeout operation timeout
     * @return see `receive_dns_packet_result`
     */
    [[nodiscard]] ReceiveDnsPacketResult receive_dns_packet(std::optional<Micros> timeout);

    operator bool() const noexcept {
        return m_event_loop->c_base();
    }

private:
    Logger m_log;
    size_t m_id = 0;
    EventLoopPtr m_event_loop = EventLoop::create(false);
    SocketFactory::SocketPtr m_underlying_socket;
    OnReadCallback m_on_read_callback = {};
    std::optional<Socket::Error> m_pending_error;

    [[nodiscard]] Socket::ConnectParameters make_underlying_connect_parameters(
            ConnectParameters &params) const;
    static void on_connected(void *arg);
    static void on_read(void *arg, Uint8View data);
    static void on_close(void *arg, std::optional<Socket::Error> error);
};

}
