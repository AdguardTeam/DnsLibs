#pragma once


#include "outbound_proxy.h"


namespace ag {

/**
 * This entity is used if an outbound proxy is not available. In that case all outgoing connection
 * are routed directly to theirs target hosts through this fake proxy object.
 */
class direct_oproxy : public outbound_proxy {
public:
    explicit direct_oproxy(struct parameters parameters);
    ~direct_oproxy() override = default;

    direct_oproxy(direct_oproxy &&) = delete;
    direct_oproxy &operator=(direct_oproxy &&) = delete;
    direct_oproxy(const direct_oproxy &) = delete;
    direct_oproxy &operator=(const direct_oproxy &) = delete;

    /**
     * Reset all active connections
     */
    void reset_connections();

private:
    mutable std::mutex guard;
    struct connection {
        direct_oproxy *proxy = nullptr;
        uint32_t id = 0;
        std::unique_ptr<socket> socket;
        connect_parameters parameters = {};
    };

    hash_map<uint32_t, connection> connections;

    [[nodiscard]] protocols_set get_supported_protocols() const override;
    [[nodiscard]] std::optional<evutil_socket_t> get_fd(uint32_t conn_id) const override;
    [[nodiscard]] std::optional<socket::error> send(uint32_t conn_id, uint8_view data) override;
    [[nodiscard]] bool set_timeout(uint32_t conn_id, std::chrono::microseconds timeout) override;
    [[nodiscard]] std::optional<socket::error> set_callbacks(uint32_t conn_id, callbacks cbx) override;
    void close_connection(uint32_t conn_id) override;
    [[nodiscard]] std::optional<socket::error> connect_to_proxy(uint32_t conn_id, const connect_parameters &parameters) override;
    [[nodiscard]] std::optional<socket::error> connect_through_proxy(uint32_t conn_id, const connect_parameters &parameters) override;

    static void on_connected(void *arg);
    static void on_read(void *arg, uint8_view data);
    static void on_close(void *arg, std::optional<socket::error> error);
};

}
