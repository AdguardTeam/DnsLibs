#pragma once


#include <ag_socket.h>
#include <ag_event_loop.h>
#include "common/logger.h"


namespace ag {

class blocking_socket {
public:
    struct on_read_callback {
        /**
         * Raised after a data chunk has been received.
         * The caller should accumulate the data itself.
         * @return true if reading must go on, false otherwise
         */
        bool (* func)(void *arg, Uint8View data);
        /** User context for the callbacks */
        void *arg;
    };

    struct connect_parameters {
        /** Address on the peer to connect to */
        const SocketAddress &peer;
        /** Operation time out value */
        std::optional<std::chrono::microseconds> timeout;
    };

    using receive_dns_packet_result = std::variant<
            /** A DNS packet if successful */
            std::vector<uint8_t>,
            /** An error if failed */
            socket::error>;

    explicit blocking_socket(socket_factory::socket_ptr socket);
    ~blocking_socket();

    /**
     * Connect to the peer
     * @param params connect parameters
     * @return some error if failed
     */
    [[nodiscard]] std::optional<socket::error> connect(connect_parameters params);

    /**
     * Send data to the peer
     * @param data the data
     * @return some error if failed
     */
    [[nodiscard]] std::optional<socket::error> send(Uint8View data);

    /**
     * Send DNS packet to the peer
     * @param data the packet
     * @return some error if failed
     */
    [[nodiscard]] std::optional<socket::error> send_dns_packet(Uint8View data);

    /**
     * Receive data from the peer.
     * Blocks until either an error happened or interrupted via `on_read_callback` by the caller.
     * @param on_read_handler read events handler
     * @param timeout operation timeout
     * @return some error if failed
     */
    [[nodiscard]] std::optional<socket::error> receive(on_read_callback on_read_handler,
            std::optional<std::chrono::microseconds> timeout);

    /**
     * Receive DNS packet from the peer.
     * Blocks until either an error happened or the packet is fully received.
     * @param timeout operation timeout
     * @return see `receive_dns_packet_result`
     */
    [[nodiscard]] receive_dns_packet_result receive_dns_packet(std::optional<std::chrono::microseconds> timeout);

    operator bool() const noexcept {
        return event_loop->c_base();
    }

private:
    Logger log;
    size_t id = 0;
    event_loop_ptr event_loop = event_loop::create(false);
    socket_factory::socket_ptr underlying_socket;
    on_read_callback on_read_callback = {};
    std::optional<socket::error> pending_error;

    [[nodiscard]] socket::connect_parameters make_underlying_connect_parameters(
            connect_parameters &params) const;
    static void on_connected(void *arg);
    static void on_read(void *arg, Uint8View data);
    static void on_close(void *arg, std::optional<socket::error> error);
};

}
