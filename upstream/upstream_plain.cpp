#include "upstream_plain.h"

#include <algorithm>
#include <cassert>
#include <utility>

#include "common/net_utils.h"
#include "common/utils.h"
#include "dns/net/aio_socket.h"
#include "dns/net/utils.h"

#include "bootstrapped_connection.h"

#define tracelog_id(l_, pkt_, fmt_, ...) tracelog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)

namespace ag::dns {

class PlainFramedConnection;

using PlainFramedConnectionPtr = std::shared_ptr<PlainFramedConnection>;

/**
 * Framed TCP connection for plain-DNS upstreams.
 * Behaves like `DnsFramedConnection`, except that when the parent upstream
 * addresses a hostname it first resolves it via the upstream's bootstrapper
 * (one IPv4 + one IPv6 candidate tried in parallel) before connecting.
 */
class PlainFramedConnection : public BootstrappedFramedConnection {
public:
    using BootstrappedFramedConnection::BootstrappedFramedConnection;

    /** Create a connection owned by the given pool. */
    static PlainFramedConnectionPtr create(
            EventLoop &loop, const ConnectionPoolPtr &pool, const std::string &address_str) {
        return std::make_shared<PlainFramedConnection>(ConstructorAccess{}, loop, pool, address_str);
    }

private:
    SocketFactory::SocketPtr make_stream(const std::shared_ptr<Upstream> &upstream) override {
        return upstream->make_socket(utils::TP_TCP);
    }

    Bootstrapper *bootstrapper(const std::shared_ptr<Upstream> &upstream) override {
        auto *plain = dynamic_cast<PlainUpstream *>(upstream.get());
        assert(plain != nullptr);
        return plain != nullptr ? plain->m_bootstrapper.get() : nullptr;
    }

    AddressVariant no_bootstrap_address(const std::shared_ptr<Upstream> &upstream) override {
        auto *plain = dynamic_cast<PlainUpstream *>(upstream.get());
        assert(plain != nullptr);
        return plain != nullptr ? plain->m_address : AddressVariant{};
    }
};

PlainUpstream::PlainUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config)
        : Upstream(opts, config)
        , m_log(AG_FMT("Plain upstream ({})", opts.address))
        , m_prefer_tcp{false}
        , m_prefer_udp{false}
        , m_shutdown_guard(std::make_shared<bool>(true)) {
}

Error<Upstream::InitError> PlainUpstream::init() {
    std::string host;
    uint16_t port = DEFAULT_PLAIN_PORT;

    if (m_options.address.find("://") != std::string::npos) {
        auto error = this->init_url_port(
                /*allow_creds*/ false, /*allow_path*/ false, DEFAULT_PLAIN_PORT, /*host_to_lowercase*/ false);
        if (error) {
            return error;
        }
        if (m_url.get_protocol() == UDP_SCHEME) {
            m_prefer_udp = true;
        } else if (m_url.get_protocol() == TCP_SCHEME) {
            m_prefer_tcp = true;
        } else {
            return make_error(InitError::AE_INVALID_ADDRESS, AG_FMT("Invalid URL scheme: {}", m_url.get_protocol()));
        }

        // Note: for the non-special `udp:`/`tcp:` schemes ada's get_host() also
        // includes the optional port, so str_to_socket_address() keeps honoring
        // an explicitly specified numeric port.
        m_address = ag::utils::str_to_socket_address(m_url.get_host());
        port = m_port;
        if (!m_address.valid()) {
            host = m_url.get_hostname();
        }
    } else {
        auto split_result = ag::utils::split_host_port(m_options.address);
        if (split_result.has_error()) {
            return make_error(InitError::AE_INVALID_ADDRESS, m_options.address);
        }
        auto [split_host, split_port] = split_result.value();
        if (!split_port.empty()) {
            auto parsed_port = ag::utils::to_integer<uint16_t>(split_port);
            if (!parsed_port.has_value()) {
                return make_error(InitError::AE_INVALID_ADDRESS, m_options.address);
            }
            port = parsed_port.value();
        }
        host = std::string(split_host);
        m_address = SocketAddress(split_host, port);
    }

    if (!std::holds_alternative<std::monostate>(m_options.resolved_server_ip)) {
        // resolved_server_ip takes precedence; the bootstrapper is not used.
        m_address = SocketAddress(m_options.resolved_server_ip, port);
    } else if (m_address.valid()) {
        if (m_address.port() == 0) {
            // Don't lose the scope ID!
            m_address.set_port(DEFAULT_PLAIN_PORT);
        }
    } else if (m_options.bootstrap.empty()) {
        return make_error(InitError::AE_EMPTY_BOOTSTRAP);
    } else {
        std::string address_string = AG_FMT("{}:{}", host, port);
        m_bootstrapper = std::make_unique<Bootstrapper>(Bootstrapper::Params{.address_string = address_string,
                .default_port = DEFAULT_PLAIN_PORT,
                .bootstrap = m_options.bootstrap,
                .timeout = m_config.timeout,
                .upstream_config = m_config,
                .outbound_interface = m_options.outbound_interface});
        if (auto err = m_bootstrapper->init(); err) {
            return make_error(InitError::AE_BOOTSTRAPPER_INIT_FAILED, err);
        }
    }

    m_pool = std::make_shared<ConnectionPool<PlainFramedConnection>>(config().loop, shared_from_this(), 10);

    return {};
}

coro::Task<Upstream::ExchangeResult> PlainUpstream::exchange(const ldns_pkt *request_pkt, const DnsMessageInfo *info) {
    std::weak_ptr<bool> guard = m_shutdown_guard;

    ldns_buffer_ptr buffer{ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY)};
    ldns_status status = ldns_pkt2buffer_wire(&*buffer, request_pkt);
    if (status != LDNS_STATUS_OK) {
        co_return make_error(DnsError::AE_ENCODE_ERROR, ldns_get_errorstr_by_id(status));
    }

    ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request_pkt), 0);
    AllocatedPtr<char> domain;
    if (question) {
        domain = AllocatedPtr<char>(ldns_rdf2str(ldns_rr_owner(question)));
        tracelog_id(m_log, request_pkt, "Querying for a domain: {}", domain.get());
    }

    utils::Timer timer;
    Millis timeout = m_config.timeout;

    if (!m_prefer_tcp && !(info && info->proto == utils::TP_TCP)) {
        AddressVariant peer = m_address;
        if (m_bootstrapper) {
            auto resolve_result = co_await m_bootstrapper->get();
            if (guard.expired()) {
                co_return make_error(DnsError::AE_SHUTTING_DOWN);
            }
            if (resolve_result.error) {
                co_return make_error(DnsError::AE_BOOTSTRAP_ERROR, resolve_result.error);
            }
            if (resolve_result.addresses.empty()) {
                co_return make_error(DnsError::AE_BOOTSTRAP_ERROR, "Bootstrapper returned an empty address list");
            }
            // Pick a single peer for the UDP request: prefer the first IPv4, fall back to IPv6.
            auto it = std::find_if(
                    resolve_result.addresses.begin(), resolve_result.addresses.end(), [](const SocketAddress &addr) {
                        return addr.is_ipv4();
                    });
            peer = it != resolve_result.addresses.end() ? *it : resolve_result.addresses.front();
        }

        // Drop the chosen peer from the bootstrap cache on any failure so the
        // next exchange rotates to another resolved address. Mirrors the TCP
        // path, which evicts the used address in `PlainFramedConnection` on
        // error. In particular, covers the common UDP failure mode -- the server
        // never replies and `receive_and_decode_dns_packet` times out.
        auto evict_peer = [&]() {
            if (m_bootstrapper) {
                if (const auto *saddr = std::get_if<SocketAddress>(&peer)) {
                    m_bootstrapper->remove_resolved(*saddr);
                }
            }
        };

        AioSocket socket(this->make_socket(utils::TP_UDP));
        auto err = co_await socket.connect({&m_config.loop, peer, timeout});
        if (guard.expired()) {
            co_return make_error(DnsError::AE_SHUTTING_DOWN);
        }
        if (err) {
            evict_peer();
            co_return (err->value() == SocketError::AE_TIMED_OUT) // To cancel second retry of exchange
                    ? make_error(DnsError::AE_TIMED_OUT, "Timed out while connecting to remote host via UDP")
                    : make_error(DnsError::AE_SOCKET_ERROR, err);
        }

        timeout -= timer.elapsed<decltype(timeout)>();
        if (timeout.count() <= 0) {
            co_return make_error(DnsError::AE_TIMED_OUT, "Timed out after connecting to remote host");
        }
        timer.reset();

        if (auto err = send_dns_packet(
                    &socket, {(uint8_t *) ldns_buffer_begin(buffer.get()), ldns_buffer_position(buffer.get())})) {
            evict_peer();
            co_return make_error(DnsError::AE_SOCKET_ERROR, err);
        }

        auto r = co_await receive_and_decode_dns_packet(
                &socket, timeout, [id = ldns_pkt_id(request_pkt)](Uint8Vector buf) {
                    ldns_pkt *reply_pkt = nullptr;
                    auto status = ldns_wire2pkt(&reply_pkt, buf.data(), buf.size());
                    // Skip incorrect packets or packets with invalid id
                    if (status != LDNS_STATUS_OK || ldns_pkt_id(reply_pkt) != id) {
                        return ldns_pkt_ptr{nullptr}; // Return nullptr wrapped in ldns_pkt_ptr
                    }
                    return ldns_pkt_ptr{reply_pkt};
                });

        if (guard.expired()) {
            co_return make_error(DnsError::AE_SHUTTING_DOWN);
        }
        if (r.has_error()) {
            evict_peer();
            co_return (r.error()->value() == SocketError::AE_TIMED_OUT) // To cancel second retry of exchange
                    ? make_error(DnsError::AE_TIMED_OUT, "Timed out while waiting for DNS reply via UDP")
                    : make_error(DnsError::AE_SOCKET_ERROR, r.error());
        }

        auto &reply_pkt = r.value();
        if (m_prefer_udp || !ldns_pkt_tc(reply_pkt.get())) {
            co_return std::move(reply_pkt);
        }
        tracelog_id(m_log, request_pkt, "Trying TCP request after UDP failure");
    }

    timeout -= timer.elapsed<decltype(timeout)>();
    if (timeout.count() <= 0) {
        co_return make_error(DnsError::AE_TIMED_OUT, "TCP request should be done but no time left");
    }

    // TCP request
    Uint8View buf{ldns_buffer_begin(buffer.get()), ldns_buffer_position(buffer.get())};
    tracelog_id(m_log, request_pkt, "Sending TCP request for a domain: {}", domain ? domain.get() : "(unknown)");
    auto result = co_await m_pool->perform_request(buf, timeout);
    if (guard.expired()) {
        co_return make_error(DnsError::AE_SHUTTING_DOWN);
    }
    if (result.has_error()) {
        co_return result.error();
    }

    const Uint8Vector &reply = result.value();
    ldns_pkt *reply_pkt = nullptr;
    status = ldns_wire2pkt(&reply_pkt, reply.data(), reply.size());
    if (status != LDNS_STATUS_OK) {
        co_return make_error(DnsError::AE_DECODE_ERROR, ldns_get_errorstr_by_id(status));
    }
    co_return ldns_pkt_ptr{reply_pkt};
}

} // namespace ag::dns
