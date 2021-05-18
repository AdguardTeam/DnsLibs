#include <ag_utils.h>
#include <ag_net_utils.h>
#include "outbound_socks_proxy.h"
#include <magic_enum.hpp>

#ifdef _WIN32
#include <ws2ipdef.h>
#endif


#define log_proxy(p_, lvl_, fmt_, ...) lvl_##log((p_)->log, "[id={}] {}(): " fmt_, (p_)->id, __func__, ##__VA_ARGS__)
#define log_conn(p_, id_, lvl_, fmt_, ...) lvl_##log((p_)->log, "[id={}/{}] {}(): " fmt_, (p_)->id, (id_), __func__, ##__VA_ARGS__)


using namespace ag;


enum socks_version_number {
    SVN_4 = 0x4,
    SVN_5 = 0x5,
};

enum socks4_command {
    S4CMD_CONNECT = 0x1,
    S4CMD_REQUEST_GRANTED = 0x90, // request granted
    // all other codes are errors
};

enum socks5_auth_method {
    S5AM_NO_AUTHENTICATION_REQUIRED = 0x00,
    S5AM_GSSAPI = 0x01,
    S5AM_USERNAME_PASSWORD = 0x02,
    S5AM_NO_ACCEPTABLE_METHODS = 0xff,
};

enum socks5_user_pass_auth_version_number {
    S5UPAVN_1 = 0x01,
};

enum socks5_user_pass_auth_status {
    S5UPAS_SUCCESS = 0x00,
};

enum socks5_command {
    S5CMD_CONNECT = 0x01,
    S5CMD_UDP_ASSOCIATE = 0x03,
};

enum socks5_address_type {
    S5AT_IPV4 = 0x01, // a version-4 IP address, with a length of 4 octets
    S5AT_IPV6 = 0x04, // a version-6 IP address, with a length of 16 octets
};

enum socks5_reply_status {
    S5RS_SUCCEEDED,
};

#pragma pack(push, 1)

struct socks4_connect_request { // NOLINT(cppcoreguidelines-pro-type-member-init)
    uint8_t ver = SVN_4; // version number
    uint8_t cd = S4CMD_CONNECT; // command code
    uint16_t dstport; // destination port number
    [[maybe_unused]] uint32_t dstip; // destination IP address
    uint8_t userid[];
};

struct socks4_connect_reply {
    uint8_t ver; // version number
    uint8_t cd; // command code
    uint16_t dstport; // destination port number
    [[maybe_unused]] uint32_t dstip; // destination IP address
};

struct socks5_auth_method_request { // NOLINT(cppcoreguidelines-pro-type-member-init)
    uint8_t ver = SVN_5; // version number
    uint8_t nmethods{}; // number of method identifier octets
    uint8_t methods[]; // methods
};

struct socks5_auth_method_response {
    uint8_t ver; // version number
    uint8_t method; // method
};

struct socks5_auth_user_pass_response {
    uint8_t ver; // version number
    uint8_t status; // verification status
};

struct socks5_connect_request { // NOLINT(cppcoreguidelines-pro-type-member-init)
    uint8_t ver = SVN_5; // set to X'05' for this version of the protocol
    uint8_t cmd; // command id
    [[maybe_unused]] uint8_t rsv; // reserved
    uint8_t atyp; // address type of following address
    uint8_t dst_addr[]; // desired destination address
    // desired destination port in network octet order
};

struct socks5_connect_reply {
    uint8_t ver; // set to X'05' for this version of the protocol
    uint8_t rep; // reply status
    [[maybe_unused]] uint8_t rsv; // reserved
    uint8_t atyp; // address type of following address
    uint8_t bnd_addr[]; // server bound address
    // server bound port in network octet order
};

struct socks5_udp_header {
    [[maybe_unused]] uint16_t rsv; // reserved
    uint8_t frag; // current fragment number
    uint8_t atyp; // address type of following addresses:
    uint8_t dst_addr[]; // desired destination address
    // desired destination port
    // user data
};

#pragma pack(pop)

enum connection_state {
    CS_IDLE,
    CS_CONNECTING_SOCKET,
    CS_CONNECTING_SOCKS,
    CS_S5_AUTHENTICATING,
    CS_S5_ESTABLISHING_TUNNEL,
    CS_CONNECTED,
};

struct socks_oproxy::connection {
    socks_oproxy *proxy;
    uint32_t id;
    connect_parameters parameters = {};
    connection_state state = CS_IDLE;
    socket_factory::socket_ptr socket;
    std::vector<uint8_t> recv_buffer;

    uint8_view get_processable_chunk(uint8_view data, size_t expected_length) {
        if (data.size() >= expected_length && this->recv_buffer.empty()) {
            // do nothing
        } else {
            this->recv_buffer.insert(this->recv_buffer.end(), data.begin(), data.end());
            if (this->recv_buffer.size() < expected_length) {
                data.remove_prefix(data.size());
            } else {
                data = { this->recv_buffer.data(), this->recv_buffer.size() };
            }
        }
        return data;
    }
};

struct socks_oproxy::udp_association { // NOLINT(cppcoreguidelines-pro-type-member-init)
    uint32_t conn_id;
    socket_address bound_addr;
};


socks_oproxy::socks_oproxy(const outbound_proxy_settings *settings, struct parameters parameters)
    : outbound_proxy(__func__, settings, std::move(parameters))
{}

socks_oproxy::~socks_oproxy() = default;

outbound_proxy::protocols_set socks_oproxy::get_supported_protocols() const {
    protocols_set protocols = 1 << utils::TP_TCP;
    if (this->settings->protocol == outbound_proxy_protocol::SOCKS5_UDP) {
        protocols.set(utils::TP_UDP);
    }
    return protocols;
}

std::optional<evutil_socket_t> socks_oproxy::get_fd(uint32_t conn_id) const {
    std::scoped_lock l(this->guard);
    auto it = this->connections.find(conn_id);
    return (it != this->connections.end() && it->second->socket != nullptr)
            ? it->second->socket->get_fd() : std::nullopt;
}

static void append_bytes(std::vector<uint8_t> &buf, const void *mem, size_t size) {
    buf.insert(buf.end(), (uint8_t *)mem, (uint8_t *)mem + size);
}

static size_t get_full_udp_header_size(const socks5_udp_header *h) {
    // domain names are not supported for now
    assert(h->atyp == S5AT_IPV4 || h->atyp == S5AT_IPV6);
    return sizeof(*h) + ((h->atyp == S5AT_IPV4) ? 4 : 16) + 2;
}

std::optional<socket::error> socks_oproxy::send(uint32_t conn_id, uint8_view data) {
    log_conn(this, conn_id, trace, "{}", data.size());

    std::scoped_lock l(this->guard);
    auto it = this->connections.find(conn_id);
    if (it == this->connections.end()) {
        return { { -1, AG_FMT("Non-existent connection: {}", conn_id) } };
    }

    std::optional<socket::error> e;

    connection *conn = it->second.get();
    switch (conn->parameters.proto) {
    case utils::TP_TCP:
        e = conn->socket->send(data);
        break;
    case utils::TP_UDP: {
        socks5_udp_header header = {};

        uint8_view addr_bytes;
        uint16_t port;
        if (const sockaddr *addr = conn->parameters.peer.c_sockaddr();
                addr->sa_family == AF_INET) {
            header.atyp = S5AT_IPV4;
            const auto *sin = (sockaddr_in *)addr;
            addr_bytes = { (uint8_t *)&sin->sin_addr, 4 };
            port = sin->sin_port;
        } else {
            header.atyp = S5AT_IPV6;
            const auto *sin = (sockaddr_in6 *)addr;
            addr_bytes = { (uint8_t *)&sin->sin6_addr, 16 };
            port = sin->sin6_port;
        }

        std::vector<uint8_t> packet;
        packet.reserve(get_full_udp_header_size(&header) + data.size());
        append_bytes(packet, &header, sizeof(header));
        append_bytes(packet, addr_bytes.data(), addr_bytes.size());
        append_bytes(packet, &port, sizeof(port));
        append_bytes(packet, data.data(), data.size());

        e = conn->socket->send({ packet.data(), packet.size() });
        break;
    }
    }

    if (e.has_value()) {
        log_conn(this, conn_id, dbg, "Failed to send data chunk");
    }

    return e;
}

bool socks_oproxy::set_timeout(uint32_t conn_id, std::chrono::microseconds timeout) {
    log_conn(this, conn_id, trace, "{}", timeout);

    std::scoped_lock l(this->guard);
    auto it = this->connections.find(conn_id);
    if (it == this->connections.end()) {
        log_conn(this, conn_id, dbg, "Non-existent connection: {}", conn_id);
        return false;
    }

    return it->second->socket->set_timeout(timeout);
}

std::optional<socket::error> socks_oproxy::set_callbacks(uint32_t conn_id, callbacks cbx) {
    log_conn(this, conn_id, trace, "...");

    std::scoped_lock l(this->guard);
    auto it = this->connections.find(conn_id);
    if (it == this->connections.end()) {
        return { { -1, AG_FMT("Non-existent connection: {}", conn_id) } };
    }

    connection *conn = it->second.get();
    conn->parameters.callbacks = cbx;
    if (auto e = it->second->socket->set_callbacks({
                (cbx.on_connected != nullptr) ? on_connected : nullptr,
                (cbx.on_read != nullptr) ? on_read : nullptr,
                (cbx.on_close != nullptr) ? on_close : nullptr,
                conn });
            e.has_value()) {
        return e;
    }

    return std::nullopt;
}

void socks_oproxy::close_connection(uint32_t conn_id) {
    log_conn(this, conn_id, trace, "...");

    std::scoped_lock l(this->guard);
    auto it = this->connections.find(conn_id);
    if (it == this->connections.end()) {
        log_conn(this, conn_id, dbg, "Connection was not found");
        return;
    }

    connection *conn = it->second.get();
    conn->parameters.loop->submit([conn] () { conn->proxy->close_connection(conn); });
}

std::optional<socket::error> socks_oproxy::connect_to_proxy(uint32_t conn_id, const connect_parameters &parameters) {
    log_conn(this, conn_id, trace, "{}:{} == {}",
            this->settings->address, this->settings->port, parameters.peer.str());

    connection *conn = nullptr;
    {
        std::scoped_lock l(this->guard);
        if (auto &c = this->connections[conn_id]; c == nullptr) {
            c = std::make_unique<connection>(connection{ this, conn_id, parameters });
            conn = c.get();
        } else {
            return { { -1, AG_FMT("Duplicate ID: {}", conn_id) } };
        }
    }

    return this->connect_to_proxy(conn);
}

std::optional<socket::error> socks_oproxy::connect_through_proxy(uint32_t conn_id, const connect_parameters &parameters) {
    log_conn(this, conn_id, trace, "{}:{} == {}",
            this->settings->address, this->settings->port, parameters.peer.str());

    std::unique_lock l(this->guard);
    auto &conn = this->connections[conn_id];
    if (conn == nullptr) {
        return { { -1, AG_FMT("Non-existent connection: {}", conn_id) } };
    }

    if (conn->state != CS_CONNECTING_SOCKET) {
        log_conn(this, conn_id, dbg, "Invalid connection state: {}", magic_enum::enum_name(conn->state));
        return { { -1, "Invalid connection state" } };
    }

    if (conn->parameters.proto == utils::TP_UDP) {
        conn->state = CS_CONNECTED;
        if (conn->parameters.callbacks.on_connected != nullptr) {
            l.unlock();
            conn->parameters.callbacks.on_connected(conn->parameters.callbacks.arg, conn->id);
            l.lock();
        }
        return std::nullopt;
    }

    std::optional<socket::error> e;
    if (this->settings->protocol == outbound_proxy_protocol::SOCKS4) {
        e = this->send_socks4_request(conn.get());
    } else {
        e = this->send_socks5_auth_method_request(conn.get());
    }

    if (e.has_value()) {
        return e;
    }

    conn->state = CS_CONNECTING_SOCKS;

    return std::nullopt;
}

void socks_oproxy::on_connected(void *arg) {
    auto *conn = (connection *)arg;
    socks_oproxy *self = conn->proxy;
    log_conn(self, conn->id, trace, "...");

    if (auto e = self->connect_through_proxy(conn->id, conn->parameters);
            e.has_value()) {
        self->handle_connection_close(conn, std::move(e));
    }
}

void socks_oproxy::on_read(void *arg, uint8_view data) {
    auto *conn = (connection *)arg;
    socks_oproxy *self = conn->proxy;
    log_conn(self, conn->id, trace, "{}", data.size());

    switch (conn->state) {
    case CS_CONNECTING_SOCKS:
        if (self->settings->protocol == outbound_proxy_protocol::SOCKS4) {
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
            self->terminate_udp_association(conn);
        } else if (conn->parameters.callbacks.on_read != nullptr) {
            if (conn->parameters.proto == utils::TP_UDP) {
                data.remove_prefix(get_full_udp_header_size((socks5_udp_header *)data.data()));
            }
            conn->parameters.callbacks.on_read(conn->parameters.callbacks.arg, data);
        } else {
            log_conn(self, conn->id, dbg, "Dropping packet ({} bytes) as read is turned off", data.size());
        }
        break;
    case CS_IDLE:
    case CS_CONNECTING_SOCKET: {
        log_conn(self, conn->id, dbg, "Invalid state: {}", magic_enum::enum_name(conn->state));
        self->handle_connection_close(conn, { { -1, "Invalid state on reading" } });
        break;
    }
    }
}

void socks_oproxy::on_close(void *arg, std::optional<socket::error> error) {
    auto *conn = (connection *)arg;
    socks_oproxy *self = conn->proxy;
    if (error.has_value()) {
        log_conn(self, conn->id, trace, "{} ({})", error->description, error->code);
    }

    self->handle_connection_close(conn, std::move(error));
}

std::optional<socket::error> socks_oproxy::connect_to_proxy(connection *conn) {
    log_conn(this, conn->id, trace, "...");

    utils::transport_protocol proto = conn->parameters.proto;
    socket_address dst_addr;
    if (proto == utils::TP_UDP) {
        assert(this->settings->protocol == outbound_proxy_protocol::SOCKS5_UDP);

        std::scoped_lock l(this->guard);
        auto assoc_it = this->udp_associations.find(conn->parameters.loop);
        bool need_to_start_assoc = assoc_it == this->udp_associations.end();
        if (!need_to_start_assoc) {
            udp_association *association = assoc_it->second.get();
            if (auto assoc_conn_it = this->connections.find(association->conn_id);
                    assoc_conn_it == this->connections.end()) {
                log_conn(this, association->conn_id, dbg,
                        "UDP association exists but related connection not found");
                assert(0);
                need_to_start_assoc = true;
            } else if (assoc_conn_it->second->state != CS_CONNECTED) {
                log_conn(this, conn->id, trace, "Postpone until UDP association completion");
                conn->state = CS_CONNECTING_SOCKET;
                return std::nullopt;
            }
        }

        if (need_to_start_assoc) {
            assert(std::none_of(this->connections.begin(), this->connections.end(),
                    [loop = conn->parameters.loop, excluding_id = conn->id] (const auto &i) {
                        return excluding_id != i.first
                                && i.second->parameters.loop == loop
                                && i.second->parameters.proto == utils::TP_UDP;
                    }));

            auto &association = this->udp_associations[conn->parameters.loop];
            association = std::make_unique<struct udp_association>();
            association->conn_id = get_next_connection_id();
            log_conn(this, association->conn_id, dbg, "Starting UDP association");

            auto &udp_association_conn = this->connections[association->conn_id];
            udp_association_conn = std::make_unique<connection>(
                    connection{ this, association->conn_id,
                            { conn->parameters.loop, utils::TP_TCP, socket_address(this->settings->address, this->settings->port),
                                    {}, conn->parameters.timeout } });
            udp_association_conn->socket = this->parameters.make_socket.func(this->parameters.make_socket.arg, utils::TP_TCP);
            proto = utils::TP_TCP;
            conn = udp_association_conn.get();
            dst_addr = conn->parameters.peer;
        } else {
            dst_addr = assoc_it->second->bound_addr;
        }
    } else {
        dst_addr = socket_address(this->settings->address, this->settings->port);
    }

    assert(dst_addr.valid());

    conn->socket = this->parameters.make_socket.func(this->parameters.make_socket.arg, proto);
    if (auto e = conn->socket->connect({ conn->parameters.loop,
                dst_addr,
                { on_connected, on_read, on_close, conn },
                conn->parameters.timeout });
            e.has_value()) {
        log_conn(this, conn->id, dbg, "Failed to start socket connection");
        return e;
    }

    conn->state = CS_CONNECTING_SOCKET;

    return std::nullopt;
}

void socks_oproxy::close_connection(connection *conn) {
    uint32_t conn_id = conn->id;
    event_loop *loop = conn->parameters.loop;
    utils::transport_protocol proto = conn->parameters.proto;

    std::scoped_lock l(this->guard);
    this->connections.erase(conn_id);

    if (proto != utils::TP_UDP) {
        return;
    }

    bool some_udp_connections_left = std::any_of(this->connections.begin(), this->connections.end(),
            [loop] (const auto &i) {
                return i.second->parameters.loop == loop && i.second->parameters.proto == utils::TP_UDP;
            });
    if (some_udp_connections_left) {
        return;
    }

    auto assoc_it = this->udp_associations.find(loop);
    if (assoc_it == this->udp_associations.end()) {
        log_conn(this, conn_id, dbg, "UDP association is not found");
        assert(0);
        return;
    }

    auto assoc_conn_it = this->connections.find(assoc_it->second->conn_id);
    if (assoc_conn_it == this->connections.end()) {
        log_conn(this, conn_id, dbg, "TCP connection of UDP association is not found");
        assert(0);
        return;
    }

    // A TCP connection of the UDP association can't be left hanging
    // because it can outlive the event loop which will cause a use-after-free
    // while destructing the connections table
    this->terminate_udp_association_silently(assoc_conn_it->second.get());
}

bool socks_oproxy::is_udp_association_connection(uint32_t conn_id) const {
    std::scoped_lock l(this->guard);
    return std::any_of(this->udp_associations.begin(), this->udp_associations.end(),
            [conn_id] (const auto &i) { return conn_id == i.second->conn_id; });
}

void socks_oproxy::handle_connection_close(connection *conn, std::optional<socket::error> error) {
    if (this->is_udp_association_connection(conn->id)) {
        if (!error.has_value() || error->code != utils::AG_ETIMEDOUT) {
            this->terminate_udp_association(conn);
        }
    } else if (conn->parameters.callbacks.on_close != nullptr) {
        conn->parameters.callbacks.on_close(conn->parameters.callbacks.arg, std::move(error));
        this->close_connection(conn);
    }
}

void socks_oproxy::on_udp_association_established(connection *assoc_conn, socket_address bound_addr) {
    log_conn(this, assoc_conn->id, trace, "...");

    std::vector<connection *> udp_connections;

    this->guard.lock();
    if (auto it = this->udp_associations.find(assoc_conn->parameters.loop);
            it != this->udp_associations.end()) {
        it->second->bound_addr = bound_addr;
    } else {
        log_conn(this, assoc_conn->id, dbg, "UDP association is not found");
        this->guard.unlock();
        this->terminate_udp_association(assoc_conn);
        return;
    }

    for (const auto &[_, conn] : this->connections) {
        if (assoc_conn->parameters.loop == conn->parameters.loop
                && conn->parameters.proto == utils::TP_UDP) {
            udp_connections.emplace_back(conn.get());
        }
    }
    this->guard.unlock();

    for (connection *conn : udp_connections) {
        if (auto e = this->connect_to_proxy(conn);
                e.has_value() && conn->parameters.callbacks.on_close != nullptr) {
            conn->parameters.callbacks.on_close(conn->parameters.callbacks.arg, std::move(e));
        }
    }
}

void socks_oproxy::terminate_udp_association(connection *assoc_conn) {
    log_conn(this, assoc_conn->id, trace, "...");

    std::vector<std::unique_ptr<connection>> udp_connections;

    this->guard.lock();
    for (auto i = this->connections.begin(); i != this->connections.end();) {
        auto &conn = i->second;
        if (assoc_conn->parameters.loop == conn->parameters.loop
                && conn->parameters.proto == utils::TP_UDP) {
            udp_connections.emplace_back(std::move(conn));
            i = this->connections.erase(i);
        } else {
            ++i;
        }
    }

    this->terminate_udp_association_silently(assoc_conn);
    this->guard.unlock();

    for (auto &conn : udp_connections) {
        if (conn->parameters.callbacks.on_close != nullptr) {
            conn->parameters.callbacks.on_close(conn->parameters.callbacks.arg,
                    { { -1, "UDP association terminated" } });
        }
    }
}

void socks_oproxy::terminate_udp_association_silently(connection *assoc_conn) {
    assert(std::none_of(this->connections.begin(), this->connections.end(),
            [loop = assoc_conn->parameters.loop] (const auto &i) {
                return i.second->parameters.loop == loop && i.second->parameters.proto == utils::TP_UDP;
            }));

    if (auto it = this->udp_associations.find(assoc_conn->parameters.loop);
            it != this->udp_associations.end()) {
        this->connections.erase(assoc_conn->id);
        this->udp_associations.erase(it);
    }
}

#define SEND_S(conn_, data_) \
    do { \
        if (auto e = (conn_)->socket->send(data_); e.has_value()) { \
            log_conn(this, (conn_)->id, dbg, "Failed to send data"); \
            return e; \
        } \
    } while (0)

std::optional<socket::error> socks_oproxy::send_socks4_request(connection *conn) {
    log_conn(this, conn->id, trace, "...");

    socks4_connect_request request = {};
    request.dstport = htons(conn->parameters.peer.port());
    request.dstip = *(uint32_t *)&((sockaddr_in *)conn->parameters.peer.c_sockaddr())->sin_addr;

    uint8_view data = { (uint8_t *)&request, sizeof(request) };
    SEND_S(conn, data);

    static constexpr char ADGUARD[] = "adguard";
    data = { (uint8_t *)&ADGUARD, sizeof(ADGUARD) };
    SEND_S(conn, data);

    return std::nullopt;
}

void socks_oproxy::on_socks4_reply(connection *conn, uint8_view data) {
    log_conn(this, conn->id, trace, "...");

    if (data.size() + conn->recv_buffer.size() > sizeof(socks4_connect_reply)) {
        log_conn(this, conn->id, dbg, "Too long: {} bytes", data.size() + conn->recv_buffer.size());
        this->handle_connection_close(conn, { { -1, "Bad reply" } });
        return;
    }

    uint8_view seek = conn->get_processable_chunk(data, sizeof(socks4_connect_reply));
    if (seek.empty()) {
        return;
    }

    const auto *reply = (socks4_connect_reply *)seek.data();
    if (reply->ver != 0x0) {
        log_conn(this, conn->id, dbg, "Malformed version number: {}", reply->ver);
        this->handle_connection_close(conn, { { -1, "Bad reply" } });
        return;
    }
    if (reply->cd != S4CMD_REQUEST_GRANTED) {
        log_conn(this, conn->id, dbg, "Bad command: {}", reply->cd);
        this->handle_connection_close(conn, { { -1, "Bad reply" } });
        return;
    }

    conn->state = CS_CONNECTED;
    conn->recv_buffer.clear();
    if (conn->parameters.callbacks.on_connected != nullptr) {
        conn->parameters.callbacks.on_connected(conn->parameters.callbacks.arg, conn->id);
    }
}

std::optional<socket::error> socks_oproxy::send_socks5_auth_method_request(connection *conn) {
    log_conn(this, conn->id, trace, "...");

    static constexpr uint8_t METHODS[] = { S5AM_NO_AUTHENTICATION_REQUIRED, S5AM_USERNAME_PASSWORD };

    socks5_auth_method_request request = {};
    request.nmethods = !this->settings->auth_info.has_value() ? 1 : 2;

    uint8_view data = { (uint8_t *)&request, sizeof(request) };
    SEND_S(conn, data);

    data = { METHODS, request.nmethods };
    SEND_S(conn, data);

    return std::nullopt;
}

void socks_oproxy::on_socks5_auth_method_response(connection *conn, uint8_view data) {
    log_conn(this, conn->id, trace, "...");

    if (data.size() + conn->recv_buffer.size() > sizeof(socks5_auth_method_response)) {
        log_conn(this, conn->id, dbg, "Too long: {} bytes", data.size() + conn->recv_buffer.size());
        this->handle_connection_close(conn, { { -1, "Bad reply" } });
        return;
    }

    uint8_view seek = conn->get_processable_chunk(data, sizeof(socks5_auth_method_response));
    if (seek.empty()) {
        return;
    }

    const auto *reply = (socks5_auth_method_response *)seek.data();
    if (reply->ver != SVN_5) {
        log_conn(this, conn->id, dbg, "Malformed version number: {}", reply->ver);
        this->handle_connection_close(conn, { { -1, "Bad reply" } });
        return;
    }
    if (reply->method != S5AM_NO_AUTHENTICATION_REQUIRED && reply->method != S5AM_USERNAME_PASSWORD) {
        log_conn(this, conn->id, dbg, "Unsupported authentication method: {}", reply->method);
        this->handle_connection_close(conn, { { -1, "Bad reply" } });
        return;
    }

    std::optional<socket::error> e;
    if (reply->method == S5AM_USERNAME_PASSWORD) {
        e = this->send_socks5_user_pass_auth_request(conn);
        conn->state = CS_S5_AUTHENTICATING;
    } else {
        e = this->send_socks5_connect_request(conn);
        conn->state = CS_S5_ESTABLISHING_TUNNEL;
    }

    conn->recv_buffer.clear();
    if (e.has_value()) {
        this->handle_connection_close(conn, std::move(e));
    }
}

// https://tools.ietf.org/html/rfc1929
std::optional<socket::error> socks_oproxy::send_socks5_user_pass_auth_request(connection *conn) {
    log_conn(this, conn->id, trace, "...");

    uint8_t ver = S5UPAVN_1;
    uint8_view data = { (uint8_t *)&ver, sizeof(ver) };
    SEND_S(conn, data);

    uint8_t ulen = this->settings->auth_info->username.size();
    data = { (uint8_t *)&ulen, sizeof(ulen) };
    SEND_S(conn, data);

    data = { (uint8_t *)this->settings->auth_info->username.data(),
            std::min(this->settings->auth_info->username.size(), (size_t)255) };
    SEND_S(conn, data);

    uint8_t plen = this->settings->auth_info->password.size();
    data = { (uint8_t *)&plen, sizeof(plen) };
    SEND_S(conn, data);

    data = { (uint8_t *)this->settings->auth_info->password.data(),
            std::min(this->settings->auth_info->password.size(), (size_t)255) };
    SEND_S(conn, data);

    return std::nullopt;
}

void socks_oproxy::on_socks5_user_pass_auth_response(connection *conn, uint8_view data) {
    log_conn(this, conn->id, trace, "...");

    if (data.size() + conn->recv_buffer.size() > sizeof(socks5_auth_user_pass_response)) {
        log_conn(this, conn->id, dbg, "Too long: {} bytes", data.size() + conn->recv_buffer.size());
        this->handle_connection_close(conn, { { -1, "Bad reply" } });
        return;
    }

    uint8_view seek = conn->get_processable_chunk(data, sizeof(socks5_auth_user_pass_response));
    if (seek.empty()) {
        return;
    }

    const auto *reply = (socks5_auth_user_pass_response *)seek.data();
    if (reply->ver != S5UPAVN_1) {
        log_conn(this, conn->id, dbg, "Malformed version number: {}", reply->ver);
        this->handle_connection_close(conn, { { -1, "Bad reply" } });
        return;
    }
    if (reply->status != S5UPAS_SUCCESS) {
        log_conn(this, conn->id, dbg, "Bad authentication status: {}", reply->status);
        this->handle_connection_close(conn, { { -1, "Bad reply" } });
        return;
    }

    std::optional<socket::error> e = this->send_socks5_connect_request(conn);
    conn->state = CS_S5_ESTABLISHING_TUNNEL;
    conn->recv_buffer.clear();

    if (e.has_value()) {
        this->handle_connection_close(conn, std::move(e));
    }
}

std::optional<socket::error> socks_oproxy::send_socks5_connect_request(connection *conn) {
    log_conn(this, conn->id, trace, "...");

    const sockaddr *addr = conn->parameters.peer.c_sockaddr();

    socks5_connect_request request = {};
    request.cmd = this->is_udp_association_connection(conn->id) ? S5CMD_UDP_ASSOCIATE : S5CMD_CONNECT;
    request.atyp = (addr->sa_family == AF_INET) ? S5AT_IPV4 : S5AT_IPV6;

    uint8_view data = { (uint8_t *)&request, sizeof(request) };
    SEND_S(conn, data);

    uint16_t port;
    if (addr->sa_family == AF_INET) {
        const auto *sin = (sockaddr_in *)addr;
        data = { (uint8_t *)&sin->sin_addr, 4 };
        port = sin->sin_port;
    } else {
        const auto *sin = (sockaddr_in6 *)addr;
        data = { (uint8_t *)&sin->sin6_addr, 16 };
        port = sin->sin6_port;
    }
    SEND_S(conn, data);

    data = { (uint8_t *)&port, sizeof(port) };
    SEND_S(conn, data);

    return std::nullopt;
}

void socks_oproxy::on_socks5_connect_response(connection *conn, uint8_view data) {
    log_conn(this, conn->id, trace, "...");

    uint8_view seek = conn->get_processable_chunk(data, sizeof(socks5_connect_reply));
    if (seek.empty()) {
        return;
    }

    const auto *reply = (socks5_connect_reply *)seek.data();
    if (reply->ver != SVN_5) {
        log_conn(this, conn->id, dbg, "Malformed version number: {}", reply->ver);
        this->handle_connection_close(conn, { { -1, "Bad reply" } });
        return;
    }
    if (reply->rep != S5RS_SUCCEEDED) {
        log_conn(this, conn->id, dbg, "Bad status: {}", reply->rep);
        this->handle_connection_close(conn, { { -1, "Bad reply" } });
        return;
    }
    if (reply->atyp != S5AT_IPV4 && reply->atyp != S5AT_IPV6) {
        log_conn(this, conn->id, dbg, "Bad address type: {}", reply->atyp);
        this->handle_connection_close(conn, { { -1, "Bad reply" } });
        return;
    }

    size_t full_length =
            sizeof(socks5_connect_reply) + ((reply->atyp == S5AT_IPV4) ? 4 : 16) + 2;
    if (seek.size() < full_length) {
        // wait full
        if (conn->recv_buffer.empty()) {
            conn->recv_buffer.insert(conn->recv_buffer.end(), data.begin(), data.end());
        }
        return;
    }
    if (seek.size() > full_length) {
        log_conn(this, conn->id, dbg, "Too long: {} bytes", seek.size());
        this->handle_connection_close(conn, { { -1, "Bad reply" } });
        return;
    }

    conn->state = CS_CONNECTED;
    conn->recv_buffer.resize(0);
    if (this->is_udp_association_connection(conn->id)) {
        uint8_view addr = { reply->bnd_addr, (size_t)((reply->atyp == S5AT_IPV4) ? 4 : 16) };
        uint16_t port = ntohs(*(uint16_t *)(reply->bnd_addr + addr.size()));

        this->on_udp_association_established(conn, socket_address(addr, port));
    } else if (conn->parameters.callbacks.on_connected != nullptr) {
        conn->parameters.callbacks.on_connected(conn->parameters.callbacks.arg, conn->id);
    }
}
