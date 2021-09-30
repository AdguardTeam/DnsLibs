#pragma once


#include <optional>
#include <mutex>
#include <ag_defs.h>
#include <tls_session_cache.h>
#include "outbound_proxy.h"


namespace ag {

class http_oproxy : public outbound_proxy {
public:
    http_oproxy(const outbound_proxy_settings *settings, struct parameters parameters);
    ~http_oproxy() override = default;

    http_oproxy(http_oproxy &&) = delete;
    http_oproxy &operator=(http_oproxy &&) = delete;
    http_oproxy(const http_oproxy &) = delete;
    http_oproxy &operator=(const http_oproxy &) = delete;

private:
    struct connection;
    mutable std::mutex guard;
    hash_map<uint32_t, std::unique_ptr<connection>> connections;
    std::optional<tls_session_cache> tls_session_cache;
    hash_map<uint32_t, std::unique_ptr<connection>> closing_connections;

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
    static int ssl_verify_callback(X509_STORE_CTX *ctx, void *arg);

    void handle_http_response_chunk(connection *conn, std::string_view chunk);
    [[nodiscard]] std::unique_ptr<SSL, ftor<&SSL_free>> make_ssl();
    callbacks get_connection_callbacks_locked(connection *conn);
};

}
