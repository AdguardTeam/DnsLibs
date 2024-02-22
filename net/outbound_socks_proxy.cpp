#include "outbound_socks_proxy.h"

#include <cassert>

#include <fmt/std.h>
#include <magic_enum/magic_enum.hpp>

#include "common/net_utils.h"
#include "common/utils.h"
#include "dns/common/dns_defs.h"

#ifdef _WIN32
#include <ws2ipdef.h>
#endif

#define log_proxy(p_, lvl_, fmt_, ...)                                                                                 \
    lvl_##log((p_)->m_log, "[id={}] {}(): " fmt_, (p_)->m_id, __func__, ##__VA_ARGS__)
#define log_conn(p_, id_, lvl_, fmt_, ...)                                                                             \
    lvl_##log((p_)->m_log, "[id={}/{}] {}(): " fmt_, (p_)->m_id, (id_), __func__, ##__VA_ARGS__)

namespace ag::dns {

enum SocksVersionNumber {
    SVN_4 = 0x4,
    SVN_5 = 0x5,
};

enum Socks4Command {
    S4CMD_CONNECT = 0x1,
    S4CMD_REQUEST_GRANTED = 0x90, // request granted
    // all other codes are errors
};

enum Socks5AuthMethod {
    S5AM_NO_AUTHENTICATION_REQUIRED = 0x00,
    S5AM_GSSAPI = 0x01,
    S5AM_USERNAME_PASSWORD = 0x02,
    S5AM_NO_ACCEPTABLE_METHODS = 0xff,
};

enum Socks5UserPassAuthVersionNumber {
    S5UPAVN_1 = 0x01,
};

enum Socks5UserPassAuthStatus {
    S5UPAS_SUCCESS = 0x00,
};

enum Socks5Command {
    S5CMD_CONNECT = 0x01,
    S5CMD_UDP_ASSOCIATE = 0x03,
};

enum Socks5AddressType {
    S5AT_IPV4 = 0x01, // a version-4 IP address, with a length of 4 octets
    S5AT_DOMAIN_NAME = 0x03, // a fully-qualified domain name, with a one-byte length prefix
    S5AT_IPV6 = 0x04, // a version-6 IP address, with a length of 16 octets
};

enum Socks5ReplyStatus {
    S5RS_SUCCEEDED,
};

#pragma pack(push, 1)

struct Socks4ConnectRequest { // NOLINT(cppcoreguidelines-pro-type-member-init)
    uint8_t ver = SVN_4; // version number
    uint8_t cd = S4CMD_CONNECT; // command code
    uint16_t dstport; // destination port number
    [[maybe_unused]] uint32_t dstip; // destination IP address
    uint8_t userid[];
};

struct Socks4ConnectReply {
    uint8_t ver; // version number
    uint8_t cd; // command code
    uint16_t dstport; // destination port number
    [[maybe_unused]] uint32_t dstip; // destination IP address
};

struct Socks5AuthMethodRequest { // NOLINT(cppcoreguidelines-pro-type-member-init)
    uint8_t ver = SVN_5; // version number
    uint8_t nmethods{}; // number of method identifier octets
    uint8_t methods[]; // methods
};

struct Socks5AuthMethodResponse {
    uint8_t ver; // version number
    uint8_t method; // method
};

struct Socks5AuthUserPassResponse {
    uint8_t ver; // version number
    uint8_t status; // verification status
};

struct Socks5ConnectRequest { // NOLINT(cppcoreguidelines-pro-type-member-init)
    uint8_t ver = SVN_5; // set to X'05' for this version of the protocol
    uint8_t cmd; // command id
    [[maybe_unused]] uint8_t rsv; // reserved
    uint8_t atyp; // address type of following address
    uint8_t dst_addr[]; // desired destination address
    // desired destination port in network octet order
};

struct Socks5ConnectReply {
    uint8_t ver; // set to X'05' for this version of the protocol
    uint8_t rep; // reply status
    [[maybe_unused]] uint8_t rsv; // reserved
    uint8_t atyp; // address type of following address
    uint8_t bnd_addr[]; // server bound address
    // server bound port in network octet order
};

struct Socks5UdpHeader {
    [[maybe_unused]] uint16_t rsv; // reserved
    uint8_t frag; // current fragment number
    uint8_t atyp; // address type of following addresses:
    uint8_t dst_addr[]; // desired destination address
    // desired destination port
    // user data
};

#pragma pack(pop)

enum ConnectionState {
    CS_IDLE,
    CS_CONNECTING_SOCKET,
    CS_CONNECTING_SOCKS,
    CS_S5_AUTHENTICATING,
    CS_S5_ESTABLISHING_TUNNEL,
    CS_CONNECTED,
    CS_CLOSING,
};

struct SocksOProxy::Connection {
    SocksOProxy *proxy;
    uint32_t id;
    ConnectParameters parameters = {};
    ConnectionState state = CS_IDLE;
    SocketFactory::SocketPtr socket;
    Uint8Vector recv_buffer;

    Uint8View get_processable_chunk(Uint8View data, size_t expected_length) {
        if (data.size() >= expected_length && this->recv_buffer.empty()) {
            // do nothing
        } else {
            this->recv_buffer.insert(this->recv_buffer.end(), data.begin(), data.end());
            if (this->recv_buffer.size() < expected_length) {
                data.remove_prefix(data.size());
            } else {
                data = {this->recv_buffer.data(), this->recv_buffer.size()};
            }
        }
        return data;
    }
};

struct SocksOProxy::UdpAssociation { // NOLINT(cppcoreguidelines-pro-type-member-init)
    uint32_t conn_id;
    SocketAddress bound_addr;
};

SocksOProxy::SocksOProxy(const OutboundProxySettings *settings, Parameters parameters)
        : OutboundProxy(__func__, settings, std::move(parameters)) {
}

SocksOProxy::~SocksOProxy() = default;

void SocksOProxy::deinit_impl() {
    std::vector<uint32_t> udp_connections, tcp_connections;
    udp_connections.reserve(m_connections.size());
    tcp_connections.reserve(m_connections.size());
    for (auto &[conn_id, conn] : m_connections) {
        if (conn->parameters.proto == utils::TP_UDP) {
            udp_connections.push_back(conn_id);
        } else {
            tcp_connections.push_back(conn_id);
        }
    }
    // We close UDP connections first, because flow of closing UDP connection here assumes that
    // in pair of UDP connection and its UDP association TCP connection,
    // UDP connection is destroyed first, then TCP connection.
    for (uint32_t conn_id : udp_connections) {
        this->SocksOProxy::close_connection_impl(conn_id);
    }
    for (uint32_t conn_id : tcp_connections) {
        this->SocksOProxy::close_connection_impl(conn_id);
    }

    assert(m_connections.empty());
    assert(m_udp_association == nullptr);
}

OutboundProxy::ProtocolsSet SocksOProxy::get_supported_protocols() const {
    ProtocolsSet protocols = 1 << utils::TP_TCP;
    protocols.set(utils::TP_UDP, m_settings->protocol == OutboundProxyProtocol::SOCKS5_UDP);
    return protocols;
}

std::optional<evutil_socket_t> SocksOProxy::get_fd(uint32_t conn_id) const {
    auto it = m_connections.find(conn_id);
    return (it != m_connections.end() && it->second->socket != nullptr) ? it->second->socket->get_fd() : std::nullopt;
}

static void append_bytes(Uint8Vector &buf, const void *mem, size_t size) {
    buf.insert(buf.end(), (uint8_t *) mem, (uint8_t *) mem + size);
}

static size_t get_full_udp_header_size(const Socks5UdpHeader *h) {
    // domain names are not supported for now
    assert(h->atyp == S5AT_IPV4 || h->atyp == S5AT_IPV6);
    return sizeof(*h) + ((h->atyp == S5AT_IPV4) ? 4 : 16) + 2;
}

Error<SocketError> SocksOProxy::send(uint32_t conn_id, Uint8View data) {
    log_conn(this, conn_id, trace, "{}", data.size());

    auto it = m_connections.find(conn_id);
    if (it == m_connections.end()) {
        return make_error(SocketError::AE_CONNECTION_ID_NOT_FOUND, fmt::to_string(conn_id));
    }

    Error<SocketError> e;

    Connection *conn = it->second.get();
    switch (conn->parameters.proto) {
    case utils::TP_TCP:
        e = conn->socket->send(data);
        break;
    case utils::TP_UDP: {
        Socks5UdpHeader header;
        memset(&header, 0, sizeof(header));

        SocketAddress unmapped;
        std::string name_storage;
        Uint8View addr_bytes;
        uint16_t port;
        if (const auto *name = std::get_if<NamePort>(&conn->parameters.peer)) {
            auto length_prefix = std::min(size_t(UINT8_MAX), name->name.size());
            name_storage.resize(name->name.size() + 1);
            name_storage[0] = (uint8_t) length_prefix;
            std::memcpy(name_storage.data() + 1, name->name.data(), length_prefix);

            header.atyp = S5AT_DOMAIN_NAME;
            addr_bytes = (uint8_t *) name_storage.data();
            port = htons(name->port);
        } else if (const auto *addr = std::get_if<SocketAddress>(&conn->parameters.peer); addr && addr->is_ipv4()) {
            unmapped = addr->socket_family_cast(AF_INET);
            header.atyp = S5AT_IPV4;
            addr_bytes = unmapped.addr();
            port = htons(unmapped.port());
        } else if (addr && addr->is_ipv6()) {
            header.atyp = S5AT_IPV6;
            addr_bytes = addr->addr();
            port = htons(addr->port());
        } else {
            e = make_error(SocketError::AE_INVALID_ARGUMENT, AG_FMT("Unsupported peer address: {}", conn->parameters.peer));
            break;
        }

        Uint8Vector packet;
        packet.reserve(get_full_udp_header_size(&header) + data.size());
        append_bytes(packet, &header, sizeof(header));
        append_bytes(packet, addr_bytes.data(), addr_bytes.size());
        append_bytes(packet, &port, sizeof(port));
        append_bytes(packet, data.data(), data.size());

        e = conn->socket->send({packet.data(), packet.size()});
        break;
    }
    }

    if (e) {
        log_conn(this, conn_id, dbg, "Failed to send data chunk");
    }

    return e;
}

bool SocksOProxy::set_timeout(uint32_t conn_id, Micros timeout) {
    log_conn(this, conn_id, trace, "{}", timeout);

    auto it = m_connections.find(conn_id);
    if (it == m_connections.end()) {
        log_conn(this, conn_id, dbg, "Non-existent connection: {}", conn_id);
        return false;
    }

    return it->second->socket->set_timeout(timeout);
}

Error<SocketError> SocksOProxy::set_callbacks_impl(uint32_t conn_id, Callbacks cbx) {
    log_conn(this, conn_id, trace, "...");

    auto it = m_connections.find(conn_id);
    if (it == m_connections.end()) {
        return make_error(SocketError::AE_CONNECTION_ID_NOT_FOUND, fmt::to_string(conn_id));
    }

    Connection *conn = it->second.get();
    conn->parameters.callbacks = cbx;
    if (auto e = it->second->socket->set_callbacks({(cbx.on_connected != nullptr) ? on_connected : nullptr,
                (cbx.on_read != nullptr) ? on_read : nullptr, (cbx.on_close != nullptr) ? on_close : nullptr, conn})) {
        return e;
    }

    return {};
}

void SocksOProxy::close_connection_impl(uint32_t conn_id) {
    log_conn(this, conn_id, trace, "...");

    auto node = m_connections.extract(conn_id);
    if (node.empty()) {
        log_conn(this, conn_id, dbg, "Connection was not found");
        return;
    }

    Connection *conn = node.mapped().get();
    if (conn->state == CS_CONNECTING_SOCKET) {
        conn->parameters.callbacks.on_proxy_connection_failed(conn->parameters.callbacks.arg, {});
    }
    conn->parameters.callbacks = {};

    this->close_connection(conn);
}

Error<SocketError> SocksOProxy::connect_to_proxy(uint32_t conn_id, const ConnectParameters &parameters) {
    log_conn(this, conn_id, trace, "{} == {}", m_resolved_proxy_address->str(), parameters.peer);

    Connection *conn = nullptr;
    if (auto &c = m_connections[conn_id]; c == nullptr) {
        c = std::make_unique<Connection>(Connection{this, conn_id, parameters});
        conn = c.get();
    } else {
        return make_error(SocketError::AE_DUPLICATE_ID, fmt::to_string(conn_id));
    }


    auto err = this->connect_to_proxy(conn);
    if (err) {
        conn->parameters.callbacks = {}; // do not raise `on_close` callback
        this->close_connection(conn);
        m_connections.erase(conn_id);
    }

    return err;
}

Error<SocketError> SocksOProxy::connect_through_proxy(uint32_t conn_id, const ConnectParameters &parameters) {
    log_conn(this, conn_id, trace, "{}:{} == {}", m_settings->address, m_settings->port, parameters.peer);

    auto &conn = m_connections[conn_id];
    if (conn == nullptr) {
        return make_error(SocketError::AE_CONNECTION_ID_NOT_FOUND, fmt::to_string(conn_id));
    }

    if (conn->state != CS_CONNECTING_SOCKET) {
        log_conn(this, conn_id, dbg, "Invalid connection state: {}", magic_enum::enum_name(conn->state));
        return make_error(SocketError::AE_INVALID_CONN_STATE, AG_FMT("id={} state={}", conn_id, magic_enum::enum_name(conn->state)));
    }

    if (conn->parameters.proto == utils::TP_UDP) {
        conn->state = CS_CONNECTED;
        if (conn->parameters.callbacks.on_connected != nullptr) {
            conn->parameters.callbacks.on_connected(conn->parameters.callbacks.arg, conn->id);
        }
        return {};
    }

    Error<SocketError> e;
    if (m_settings->protocol == OutboundProxyProtocol::SOCKS4) {
        e = this->send_socks4_request(conn.get());
    } else {
        e = this->send_socks5_auth_method_request(conn.get());
    }

    if (e) {
        return e;
    }

    conn->state = CS_CONNECTING_SOCKS;

    return {};
}

void SocksOProxy::on_connected(void *arg) {
    auto *conn = (Connection *) arg;
    SocksOProxy *self = conn->proxy;
    log_conn(self, conn->id, trace, "...");

    if (std::optional<Callbacks> cbx = self->get_connection_callbacks_locked(conn);
            cbx.has_value() && cbx->on_successful_proxy_connection != nullptr) {
        cbx->on_successful_proxy_connection(cbx->arg);
    }

    if (auto err = self->connect_through_proxy(conn->id, conn->parameters)) {
        self->handle_connection_close(conn, std::move(err));
    }
}

void SocksOProxy::on_read(void *arg, Uint8View data) {
    auto *conn = (Connection *) arg;
    SocksOProxy *self = conn->proxy;
    log_conn(self, conn->id, trace, "{}", data.size());

    switch (conn->state) {
    case CS_CONNECTING_SOCKS:
        if (self->m_settings->protocol == OutboundProxyProtocol::SOCKS4) {
            self->on_socks4_reply(conn, data);
        } else {
            self->on_socks5_auth_method_response(conn, data);
        }
        break;
    case CS_S5_AUTHENTICATING:
        self->on_socks5_user_pass_auth_response(conn, data);
        break;
    case CS_S5_ESTABLISHING_TUNNEL:
        self->on_socks5_connect_response(conn, data);
        break;
    case CS_CONNECTED:
        if (self->is_udp_association_connection(conn->id)) {
            log_conn(self, conn->id, dbg, "Unexpected data ({} bytes) on UDP association connection", data.size());
            auto error = make_error(SocketError::AE_UNEXPECTED_DATA, AG_FMT("Unexpected data ({} bytes) on UDP association connection", data.size()));
            self->terminate_udp_association(conn, error);
        } else if (std::optional<Callbacks> cbx = self->get_connection_callbacks_locked(conn);
                cbx.has_value() && cbx->on_read != nullptr) {
            if (conn->parameters.proto == utils::TP_UDP) {
                data.remove_prefix(get_full_udp_header_size((Socks5UdpHeader *) data.data()));
            }
            cbx->on_read(cbx->arg, data);
        } else {
            log_conn(self, conn->id, dbg, "Dropping packet ({} bytes) as read is turned off", data.size());
        }
        break;
    case CS_IDLE:
    case CS_CONNECTING_SOCKET:
    case CS_CLOSING: {
        log_conn(self, conn->id, dbg, "Invalid state: {}", magic_enum::enum_name(conn->state));
        auto error = make_error(SocketError::AE_INVALID_CONN_STATE, AG_FMT("id={} state={}", conn->id, magic_enum::enum_name(conn->state)));
        self->handle_connection_close(conn, error);
        break;
    }
    }
}

void SocksOProxy::on_close(void *arg, Error<SocketError> error) {
    auto *conn = (Connection *) arg;
    SocksOProxy *self = conn->proxy;
    if (error) {
        log_conn(self, conn->id, trace, "{}", error->str());
    }

    self->handle_connection_close(conn, std::move(error));
}

Error<SocketError> SocksOProxy::connect_to_proxy(Connection *conn) {
    log_conn(this, conn->id, trace, "...");

    utils::TransportProtocol proto = conn->parameters.proto;
    SocketAddress dst_addr;
    if (proto == utils::TP_UDP) {
        assert(m_settings->protocol == OutboundProxyProtocol::SOCKS5_UDP);

        bool need_to_start_assoc = m_udp_association == nullptr;
        if (!need_to_start_assoc) {
            if (auto assoc_conn_it = m_connections.find(m_udp_association->conn_id); assoc_conn_it == m_connections.end()) {
                log_conn(this, m_udp_association->conn_id, dbg, "UDP association exists but related connection not found");
                assert(0);
                need_to_start_assoc = true;
            } else if (assoc_conn_it->second->state != CS_CONNECTED) {
                log_conn(this, conn->id, trace, "Postpone until UDP association completion");
                conn->state = CS_CONNECTING_SOCKET;
                return {};
            }
        }

        if (need_to_start_assoc) {
            assert(std::none_of(m_connections.begin(), m_connections.end(),
                    [loop = conn->parameters.loop, excluding_id = conn->id](const auto &i) {
                        return excluding_id != i.first && i.second->parameters.loop == loop
                                && i.second->parameters.proto == utils::TP_UDP;
                    }));

            m_udp_association = std::make_unique<UdpAssociation>();
            m_udp_association->conn_id = get_next_connection_id();
            log_conn(this, m_udp_association->conn_id, dbg, "Starting UDP association");

            auto &udp_association_conn = m_connections[m_udp_association->conn_id];
            udp_association_conn = std::make_unique<Connection>(Connection{
                    this,
                    m_udp_association->conn_id,
                    {
                            conn->parameters.loop,
                            utils::TP_TCP,
                            m_resolved_proxy_address.value(),
                            conn->parameters.callbacks,
                            conn->parameters.timeout,
                    },
            });
            proto = utils::TP_TCP;
            conn = udp_association_conn.get();
            dst_addr = m_resolved_proxy_address.value();
        } else {
            dst_addr = m_udp_association->bound_addr;
        }
    } else {
        dst_addr = m_resolved_proxy_address.value();
    }

    assert(dst_addr.valid());

    conn->socket = m_parameters.make_socket.func(m_parameters.make_socket.arg, proto, std::nullopt);
    if (auto e = conn->socket->connect(
                {conn->parameters.loop, dst_addr, {on_connected, on_read, on_close, conn}, conn->parameters.timeout})) {
        log_conn(this, conn->id, dbg, "Failed to start socket connection");
        return e;
    }

    conn->state = CS_CONNECTING_SOCKET;

    return {};
}

void SocksOProxy::close_connection(Connection *conn) {
    uint32_t conn_id = conn->id;
    EventLoop *loop = conn->parameters.loop;
    utils::TransportProtocol proto = conn->parameters.proto;
    if (proto != utils::TP_UDP) {
        return;
    }

    bool some_other_udp_connections_left
            = std::any_of(m_connections.begin(), m_connections.end(), [conn_id, loop](const auto &i) {
                  return conn_id != i.first && i.second->parameters.loop == loop
                          && i.second->parameters.proto == utils::TP_UDP;
              });
    if (some_other_udp_connections_left || m_connections.empty()) {
        return;
    }

    if (m_udp_association == nullptr) {
        log_conn(this, conn_id, dbg, "UDP association is not started");
        assert(0);
        return;
    }

    auto assoc_conn_it = m_connections.find(m_udp_association->conn_id);
    if (assoc_conn_it == m_connections.end()) {
        log_conn(this, conn_id, dbg, "TCP connection of UDP association is not found");
        assert(0);
        return;
    }

    // A TCP connection of the UDP association can't be left hanging
    // because it can outlive the event loop which will cause a use-after-free
    // while destructing the connections table
    this->terminate_udp_association_silently(assoc_conn_it->second.get(), conn_id);
}

bool SocksOProxy::is_udp_association_connection(uint32_t conn_id) const {
    return m_udp_association != nullptr && m_udp_association->conn_id == conn_id;
}

void SocksOProxy::handle_connection_close(Connection *conn, Error<SocketError> error) {
    if (error) {
        log_conn(this, conn->id, dbg, "{}", error->str());
    }

    std::optional<Callbacks> callbacks = this->get_connection_callbacks_locked(conn);
    if (!callbacks.has_value()) {
        log_conn(this, conn->id, dbg, "Skipping event as connection is closing");
        return;
    }

    if (conn->state == CS_CONNECTING_SOCKET && callbacks->on_proxy_connection_failed != nullptr) {
        callbacks->on_proxy_connection_failed(callbacks->arg, error);
    }

    if (this->is_udp_association_connection(conn->id)) {
        if (conn->state != CS_CONNECTED || !error || error->value() != SocketError::AE_TIMED_OUT) {
            this->terminate_udp_association(conn, std::move(error));
        }
        return;
    }

    conn->state = CS_CLOSING;

    if (callbacks->on_close != nullptr) {
        callbacks->on_close(callbacks->arg, std::move(error));
    }
}

void SocksOProxy::on_udp_association_established(Connection *assoc_conn, SocketAddress bound_addr) {
    log_conn(this, assoc_conn->id, trace, "...");

    std::vector<Connection *> udp_connections;

    if (m_udp_association != nullptr) {
        m_udp_association->bound_addr = bound_addr;
    } else {
        log_conn(this, assoc_conn->id, dbg, "UDP association is not active");
        auto error = make_error(SocketError::AE_UDP_ASSOCIATION_NOT_FOUND);
        this->terminate_udp_association(assoc_conn, error);
        return;
    }

    for (const auto &[_, conn] : m_connections) {
        if (assoc_conn->parameters.loop == conn->parameters.loop && conn->parameters.proto == utils::TP_UDP) {
            udp_connections.emplace_back(conn.get());
        }
    }

    for (Connection *conn : udp_connections) {
        auto e = this->connect_to_proxy(conn);
        if (e) {
            if (std::optional<Callbacks> cbx = this->get_connection_callbacks_locked(conn);
                    cbx.has_value() && cbx->on_close != nullptr) {
                cbx->on_close(cbx->arg, std::move(e));
            }
        }
    }
}

void SocksOProxy::terminate_udp_association(Connection *assoc_conn, Error<SocketError> error) {
    log_conn(this, assoc_conn->id, trace, "...");

    std::vector<Callbacks> udp_connections_callbacks;
    for (auto i = m_connections.begin(); i != m_connections.end();) {
        auto &conn = i->second;
        if (assoc_conn->parameters.loop == conn->parameters.loop && conn->parameters.proto == utils::TP_UDP) {
            udp_connections_callbacks.emplace_back(conn->parameters.callbacks);
            i = m_connections.erase(i);
        } else {
            ++i;
        }
    }

    this->terminate_udp_association_silently(assoc_conn, std::nullopt);

    for (auto &cbx : udp_connections_callbacks) {
        if (cbx.on_close != nullptr) {
            cbx.on_close(cbx.arg, make_error(SocketError::AE_UDP_ASSOCIATION_TERMINATED, error));
        }
    }
}

void SocksOProxy::terminate_udp_association_silently(
        Connection *assoc_conn, std::optional<uint32_t> initiated_conn_id) {
    assert(std::none_of(m_connections.begin(), m_connections.end(),
            [initiated_conn_id, loop = assoc_conn->parameters.loop](const auto &i) {
                return initiated_conn_id != i.first && i.second->parameters.loop == loop
                        && i.second->parameters.proto == utils::TP_UDP;
            }));

    if (m_udp_association != nullptr) {
        m_connections.erase(m_udp_association->conn_id);
        m_udp_association.reset();
    }
}

std::optional<SocksOProxy::Callbacks> SocksOProxy::get_connection_callbacks_locked(Connection *conn) {
    return m_connections.contains(conn->id) ? std::make_optional(conn->parameters.callbacks) : std::nullopt;
}

#define SEND_S(conn_, data_)                                                                                           \
    do {                                                                                                               \
        if (auto e = (conn_)->socket->send(data_)) {                                                                   \
            log_conn(this, (conn_)->id, dbg, "Failed to send data");                                                   \
            return e;                                                                                                  \
        }                                                                                                              \
    } while (0)

Error<SocketError> SocksOProxy::send_socks4_request(Connection *conn) {
    log_conn(this, conn->id, trace, "...");

    const auto *peer = std::get_if<SocketAddress>(&conn->parameters.peer);
    if (!peer || !peer->is_ipv4()) {
        return make_error(SocketError::AE_INVALID_ARGUMENT, AG_FMT("Unsupported peer address: {}", conn->parameters.peer));
    }
    SocketAddress unmapped = peer->socket_family_cast(AF_INET);

    Socks4ConnectRequest request = {};
    request.dstport = htons(unmapped.port());
    std::memcpy(&request.dstip, unmapped.addr().data(), unmapped.addr().size());

    Uint8View data = {(uint8_t *) &request, sizeof(request)};
    SEND_S(conn, data);

    static constexpr char ADGUARD[] = "adguard";
    data = {(uint8_t *) &ADGUARD, sizeof(ADGUARD)};
    SEND_S(conn, data);

    return {};
}

void SocksOProxy::on_socks4_reply(Connection *conn, Uint8View data) {
    log_conn(this, conn->id, trace, "...");

    if (data.size() + conn->recv_buffer.size() > sizeof(Socks4ConnectReply)) {
        log_conn(this, conn->id, dbg, "Too long: {} bytes", data.size() + conn->recv_buffer.size());
        this->handle_connection_close(conn, make_error(SocketError::AE_BAD_PROXY_REPLY));
        return;
    }

    Uint8View seek = conn->get_processable_chunk(data, sizeof(Socks4ConnectReply));
    if (seek.empty()) {
        return;
    }

    const auto *reply = (Socks4ConnectReply *) seek.data();
    if (reply->ver != 0x0) {
        log_conn(this, conn->id, dbg, "Malformed version number: {}", reply->ver);
        this->handle_connection_close(conn, make_error(SocketError::AE_BAD_PROXY_REPLY));
        return;
    }
    if (reply->cd != S4CMD_REQUEST_GRANTED) {
        log_conn(this, conn->id, dbg, "Bad command: {}", reply->cd);
        this->handle_connection_close(conn, make_error(SocketError::AE_BAD_PROXY_REPLY));
        return;
    }

    conn->state = CS_CONNECTED;
    conn->recv_buffer.clear();
    if (std::optional<Callbacks> cbx = this->get_connection_callbacks_locked(conn);
            cbx.has_value() && cbx->on_connected != nullptr) {
        cbx->on_connected(cbx->arg, conn->id);
    }
}

Error<SocketError> SocksOProxy::send_socks5_auth_method_request(Connection *conn) {
    log_conn(this, conn->id, trace, "...");

    static constexpr uint8_t METHODS[] = {S5AM_NO_AUTHENTICATION_REQUIRED, S5AM_USERNAME_PASSWORD};

    Socks5AuthMethodRequest request = {};
    request.nmethods = !m_settings->auth_info.has_value() ? 1 : 2;

    Uint8View data = {(uint8_t *) &request, sizeof(request)};
    SEND_S(conn, data);

    data = {METHODS, request.nmethods};
    SEND_S(conn, data);

    return {};
}

void SocksOProxy::on_socks5_auth_method_response(Connection *conn, Uint8View data) {
    log_conn(this, conn->id, trace, "...");

    if (data.size() + conn->recv_buffer.size() > sizeof(Socks5AuthMethodResponse)) {
        log_conn(this, conn->id, dbg, "Too long: {} bytes", data.size() + conn->recv_buffer.size());
        this->handle_connection_close(conn, make_error(SocketError::AE_BAD_PROXY_REPLY));
        return;
    }

    Uint8View seek = conn->get_processable_chunk(data, sizeof(Socks5AuthMethodResponse));
    if (seek.empty()) {
        return;
    }

    const auto *reply = (Socks5AuthMethodResponse *) seek.data();
    if (reply->ver != SVN_5) {
        log_conn(this, conn->id, dbg, "Malformed version number: {}", reply->ver);
        this->handle_connection_close(conn, make_error(SocketError::AE_BAD_PROXY_REPLY));
        return;
    }
    if (reply->method != S5AM_NO_AUTHENTICATION_REQUIRED && reply->method != S5AM_USERNAME_PASSWORD) {
        log_conn(this, conn->id, dbg, "Unsupported authentication method: {}", reply->method);
        this->handle_connection_close(conn, make_error(SocketError::AE_BAD_PROXY_REPLY));
        return;
    }

    Error<SocketError> e;
    if (reply->method == S5AM_USERNAME_PASSWORD) {
        e = this->send_socks5_user_pass_auth_request(conn);
        conn->state = CS_S5_AUTHENTICATING;
    } else {
        e = this->send_socks5_connect_request(conn);
        conn->state = CS_S5_ESTABLISHING_TUNNEL;
    }

    conn->recv_buffer.clear();
    if (e) {
        this->handle_connection_close(conn, std::move(e));
    }
}

// https://tools.ietf.org/html/rfc1929
Error<SocketError> SocksOProxy::send_socks5_user_pass_auth_request(Connection *conn) {
    log_conn(this, conn->id, trace, "...");

    uint8_t ver = S5UPAVN_1;
    Uint8View data = {(uint8_t *) &ver, sizeof(ver)};
    SEND_S(conn, data);

    uint8_t ulen = m_settings->auth_info->username.size();
    data = {(uint8_t *) &ulen, sizeof(ulen)};
    SEND_S(conn, data);

    data = {(uint8_t *) m_settings->auth_info->username.data(),
            std::min(m_settings->auth_info->username.size(), (size_t) 255)};
    SEND_S(conn, data);

    uint8_t plen = m_settings->auth_info->password.size();
    data = {(uint8_t *) &plen, sizeof(plen)};
    SEND_S(conn, data);

    data = {(uint8_t *) m_settings->auth_info->password.data(),
            std::min(m_settings->auth_info->password.size(), (size_t) 255)};
    SEND_S(conn, data);

    return {};
}

void SocksOProxy::on_socks5_user_pass_auth_response(Connection *conn, Uint8View data) {
    log_conn(this, conn->id, trace, "...");

    if (data.size() + conn->recv_buffer.size() > sizeof(Socks5AuthUserPassResponse)) {
        log_conn(this, conn->id, dbg, "Too long: {} bytes", data.size() + conn->recv_buffer.size());
        this->handle_connection_close(conn, make_error(SocketError::AE_BAD_PROXY_REPLY));
        return;
    }

    Uint8View seek = conn->get_processable_chunk(data, sizeof(Socks5AuthUserPassResponse));
    if (seek.empty()) {
        return;
    }

    const auto *reply = (Socks5AuthUserPassResponse *) seek.data();
    if (reply->ver != S5UPAVN_1) {
        log_conn(this, conn->id, dbg, "Malformed version number: {}", reply->ver);
        this->handle_connection_close(conn, make_error(SocketError::AE_BAD_PROXY_REPLY));
        return;
    }
    if (reply->status != S5UPAS_SUCCESS) {
        log_conn(this, conn->id, dbg, "Bad authentication status: {}", reply->status);
        this->handle_connection_close(conn, make_error(SocketError::AE_BAD_PROXY_REPLY));
        return;
    }

    Error<SocketError> e = this->send_socks5_connect_request(conn);
    conn->state = CS_S5_ESTABLISHING_TUNNEL;
    conn->recv_buffer.clear();

    if (e) {
        this->handle_connection_close(conn, std::move(e));
    }
}

Error<SocketError> SocksOProxy::send_socks5_connect_request(Connection *conn) {
    log_conn(this, conn->id, trace, "...");

    Socks5ConnectRequest request = {};
    request.cmd = this->is_udp_association_connection(conn->id) ? S5CMD_UDP_ASSOCIATE : S5CMD_CONNECT;

    std::string name_storage;
    SocketAddress unmapped;
    uint16_t port;
    Uint8View addr_bytes;
    if (const auto *name = std::get_if<NamePort>(&conn->parameters.peer)) {
        auto length_prefix = std::min(size_t(UINT8_MAX), name->name.size());
        name_storage.resize(name->name.size() + 1);
        name_storage[0] = (uint8_t) length_prefix;
        std::memcpy(name_storage.data() + 1, name->name.data(), length_prefix);

        request.atyp = S5AT_DOMAIN_NAME;
        addr_bytes = (uint8_t *) name_storage.data();
        port = htons(name->port);
    } else if (const auto *addr = std::get_if<SocketAddress>(&conn->parameters.peer); addr && addr->is_ipv4()) {
        unmapped = addr->socket_family_cast(AF_INET);
        request.atyp = S5AT_IPV4;
        addr_bytes = unmapped.addr();
        port = htons(unmapped.port());
    } else if (addr && addr->is_ipv6()) {
        request.atyp = S5AT_IPV6;
        addr_bytes = addr->addr();
        port = htons(addr->port());
    } else {
        return make_error(SocketError::AE_INVALID_ARGUMENT, AG_FMT("Unsupported peer address: {}", conn->parameters.peer));
    }
    Uint8View data = {(uint8_t *) &request, sizeof(request)};
    SEND_S(conn, data);
    SEND_S(conn, addr_bytes);
    data = {(uint8_t *) &port, sizeof(port)};
    SEND_S(conn, data);

    return {};
}

void SocksOProxy::on_socks5_connect_response(Connection *conn, Uint8View data) {
    log_conn(this, conn->id, trace, "...");

    Uint8View seek = conn->get_processable_chunk(data, sizeof(Socks5ConnectReply));
    if (seek.empty()) {
        return;
    }

    const auto *reply = (Socks5ConnectReply *) seek.data();
    if (reply->ver != SVN_5) {
        log_conn(this, conn->id, dbg, "Malformed version number: {}", reply->ver);
        this->handle_connection_close(conn, make_error(SocketError::AE_BAD_PROXY_REPLY));
        return;
    }
    if (reply->rep != S5RS_SUCCEEDED) {
        log_conn(this, conn->id, dbg, "Bad status: {}", reply->rep);
        this->handle_connection_close(conn, make_error(SocketError::AE_BAD_PROXY_REPLY));
        return;
    }

    size_t full_length = sizeof(Socks5ConnectReply) + /*port*/2;
    switch (reply->atyp) {
    case S5AT_IPV4:
        full_length += 4;
        break;
    case S5AT_DOMAIN_NAME:
        full_length += 1;
        if (seek.size() < full_length) {
            // wait full
            if (conn->recv_buffer.empty()) {
                conn->recv_buffer.insert(conn->recv_buffer.end(), data.begin(), data.end());
            }
            return;
        }
        full_length += seek[sizeof(Socks5ConnectReply)];
        break;
    case S5AT_IPV6:
        full_length += 16;
        break;
    default:
        log_conn(this, conn->id, dbg, "Bad address type: {}", reply->atyp);
        this->handle_connection_close(conn, make_error(SocketError::AE_BAD_PROXY_REPLY));
        return;
    }

    if (seek.size() < full_length) {
        // wait full
        if (conn->recv_buffer.empty()) {
            conn->recv_buffer.insert(conn->recv_buffer.end(), data.begin(), data.end());
        }
        return;
    }
    seek.remove_prefix(full_length);

    conn->state = CS_CONNECTED;
    if (this->is_udp_association_connection(conn->id)) {
        if (!seek.empty()) {
            log_conn(this, conn->id, dbg, "Reply too long: {} bytes", seek.size());
            this->handle_connection_close(conn, make_error(SocketError::AE_BAD_PROXY_REPLY));
            return;
        }
        conn->recv_buffer.resize(0);

        Uint8View addr = {reply->bnd_addr, (size_t) ((reply->atyp == S5AT_IPV4) ? 4 : 16)};
        uint16_t port = ntohs(*(uint16_t *) (reply->bnd_addr + addr.size()));

        this->on_udp_association_established(conn, SocketAddress(addr, port));
    } else if (std::optional<Callbacks> cbx = this->get_connection_callbacks_locked(conn);
            cbx.has_value() && cbx->on_connected != nullptr) {
        cbx->on_connected(cbx->arg, conn->id);
        if (!seek.empty()) {
            cbx->on_read(cbx->arg, seek);
        }
        conn->recv_buffer.resize(0);
    }
}

} // namespace ag::dns
