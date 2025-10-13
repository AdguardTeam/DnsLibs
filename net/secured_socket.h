#pragma once


#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "common/defs.h"
#include "dns/net/socket.h"
#include "common/logger.h"
#include "tls_codec.h"


namespace ag::dns {


class SecuredSocket : public Socket {
public:
    SecuredSocket(SocketFactory::SocketPtr underlying_socket,
                  const CertificateVerifier *cert_verifier,
                  SocketFactory::SecureSocketParameters secure_parameters);
    ~SecuredSocket() override = default;

private:
    enum State : int;

    State m_state;
    WithMtx<Callbacks> m_callbacks;
    SocketFactory::SocketPtr m_underlying_socket;
    TlsCodec m_codec;
    std::string m_sni;
    std::vector<std::string> m_alpn;
    bool m_enable_pq = false;
    Logger m_log;
    std::shared_ptr<bool> m_shutdown_guard;

    [[nodiscard]] std::optional<std::string> get_alpn() const override;
    [[nodiscard]] std::optional<evutil_socket_t> get_fd() const override;
    [[nodiscard]] Error<SocketError> connect(ConnectParameters params) override;
    [[nodiscard]] Error<SocketError> send(Uint8View data) override;
    [[nodiscard]] bool set_timeout(Micros timeout) override;
    [[nodiscard]] Error<SocketError> set_callbacks(Callbacks cbx) override;

    static void on_connected(void *arg);
    static void on_read(void *arg, Uint8View data);
    static void on_close(void *arg, Error<SocketError> error);

    ConnectParameters make_underlying_connect_parameters(ConnectParameters &params) const;
    struct Callbacks get_callbacks();
    Error<SocketError> flush_pending_encrypted_data();
};


} // namespace ag::dns
