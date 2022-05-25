#pragma once


#include <mutex>
#include <vector>
#include <string>
#include "common/defs.h"
#include "net/socket.h"
#include "common/logger.h"
#include "tls_codec.h"


namespace ag {


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
    Logger m_log;

    [[nodiscard]] std::optional<evutil_socket_t> get_fd() const override;
    [[nodiscard]] std::optional<Error> connect(ConnectParameters params) override;
    [[nodiscard]] std::optional<Error> send(Uint8View data) override;
    [[nodiscard]] std::optional<Error> send_dns_packet(Uint8View data) override;
    [[nodiscard]] bool set_timeout(Micros timeout) override;
    [[nodiscard]] std::optional<Error> set_callbacks(Callbacks cbx) override;

    static void on_connected(void *arg);
    static void on_read(void *arg, Uint8View data);
    static void on_close(void *arg, std::optional<Socket::Error> error);

    ConnectParameters make_underlying_connect_parameters(ConnectParameters &params) const;
    struct Callbacks get_callbacks();
    std::optional<Error> flush_pending_encrypted_data();
};


} // namespace ag
