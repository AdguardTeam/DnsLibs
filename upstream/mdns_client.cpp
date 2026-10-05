#include "mdns_client.h"

#include <algorithm>
#include <array>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <ldns/ldns.h>
#include <uv.h>

#ifndef _WIN32
#include <net/if.h>
#endif

#include "common/logger.h"
#include "common/utils.h"
#include "dns/common/uv_wrapper.h"
#include "dns/upstream/upstream_utils.h"

namespace ag::dns {

static Logger g_log{"MdnsClient"};

using LdnsRrListPtr = UniquePtr<ldns_rr_list, &ldns_rr_list_deep_free>;

namespace {

constexpr uint16_t UNICAST_RESPONSE_BIT = 0x8000;
constexpr size_t MAX_PACKET_SIZE = 4096;
constexpr Millis RETRANSMIT_INTERVAL{1000};
constexpr const char *MDNS_GROUP_V4 = "224.0.0.251";
constexpr const char *MDNS_GROUP_V6 = "ff02::fb";

/** A link-local IPv6 interface usable for mDNS. */
struct MdnsInterface {
    std::string name;
    uint32_t index = 0;
};

/**
 * Returns the non-internal interfaces that have a link-local IPv6 address. mDNS is link-local,
 * so this both selects the interfaces mDNS should run on and filters out most tunnels/VPNs.
 */
std::vector<MdnsInterface> find_ipv6_interfaces() {
    uv_interface_address_t *addresses = nullptr;
    int count = 0;
    if (0 != uv_interface_addresses(&addresses, &count)) {
        return {};
    }

    std::vector<MdnsInterface> result;
    for (int i = 0; i < count; i++) {
        const uv_interface_address_t &iface = addresses[i];
        if (iface.is_internal || iface.address.address4.sin_family != AF_INET6) {
            continue;
        }
        if (!IN6_IS_ADDR_LINKLOCAL(&iface.address.address6.sin6_addr)) {
            continue;
        }
        uint32_t index = if_nametoindex(iface.name);
        if (index == 0) {
            continue;
        }
        bool known = std::any_of(result.begin(), result.end(), [index](const MdnsInterface &e) {
            return e.index == index;
        });
        if (!known) {
            result.push_back({iface.name, index});
        }
    }

    uv_free_interface_addresses(addresses, count);
    return result;
}

/** Builds a scoped (link-local) IPv6 address for the given interface index. */
SocketAddress make_scoped_address(const char *host, uint16_t port, uint32_t scope_id) {
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_scope_id = scope_id;
    if (0 != uv_inet_pton(AF_INET6, host, &addr.sin6_addr)) {
        return SocketAddress("::", 0);
    }
    return SocketAddress(reinterpret_cast<const sockaddr *>(&addr));
}

/**
 * `uv_udp_set_membership()`/`uv_udp_set_multicast_interface()` parse their interface argument
 * with `uv_ip6_addr()`, which expects an interface name on Unix and a numeric index on Windows.
 */
std::string multicast_interface_arg(const MdnsInterface &iface) {
#ifdef _WIN32
    return AG_FMT("::%{}", iface.index);
#else
    return AG_FMT("::%{}", iface.name);
#endif
}

/** Returns the owner name of `rr` in presentation format, or an empty string. */
std::string rr_owner(const ldns_rr *rr) {
    AllocatedPtr<char> owner{ldns_rdf2str(ldns_rr_owner(rr))};
    return owner != nullptr ? std::string(owner.get()) : std::string{};
}

/** Returns the CNAME target of `rr`, or an empty string if `rr` is not a CNAME. */
std::string cname_target(const ldns_rr *rr) {
    if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_CNAME || ldns_rr_rd_count(rr) < 1) {
        return {};
    }
    AllocatedPtr<char> target{ldns_rdf2str(ldns_rr_rdf(rr, 0))};
    return target != nullptr ? std::string(target.get()) : std::string{};
}

/** Returns true if `name` is one of `owners` (case-insensitive). */
bool is_related_owner(const std::vector<std::string> &owners, std::string_view name) {
    return std::any_of(owners.begin(), owners.end(), [name](const std::string &owner) {
        return utils::iequals(owner, name);
    });
}

/**
 * Builds the wire-format mDNS query for `request`. The unicast-response (QU) bit is only set
 * on the initial transmission (RFC 6762 §5.4 says it should not be set on retransmissions).
 */
bool build_mdns_query(const ldns_pkt *request, bool unicast_response, Uint8Vector &out, std::string &error) {
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    if (question == nullptr) {
        error = "Request has no question";
        return false;
    }

    ldns_pkt *query = ldns_pkt_new();
    ldns_pkt_set_id(query, 0);
    ldns_pkt_set_opcode(query, LDNS_PACKET_QUERY);
    ldns_pkt_set_rd(query, false);

    ldns_rr *query_question = ldns_rr_clone(question);
    if (unicast_response) {
        ldns_rr_set_class(query_question,
                static_cast<ldns_rr_class>(
                        static_cast<uint16_t>(ldns_rr_get_class(query_question)) | UNICAST_RESPONSE_BIT));
    }
    ldns_rr_list *questions = ldns_rr_list_new();
    ldns_rr_list_push_rr(questions, query_question);
    ldns_pkt_set_question(query, questions);
    // ldns_pkt_set_question() does not update the section count, but the wire header is
    // built from it.
    ldns_pkt_set_qdcount(query, 1);

    uint8_t *wire = nullptr;
    size_t wire_size = 0;
    ldns_status status = ldns_pkt2wire(&wire, query, &wire_size);
    ldns_pkt_free(query);
    AllocatedPtr<uint8_t> wire_ptr{wire};
    if (status != LDNS_STATUS_OK || wire_ptr == nullptr) {
        error = ldns_get_errorstr_by_id(status);
        return false;
    }
    out.assign(wire_ptr.get(), wire_ptr.get() + wire_size);
    return true;
}

} // namespace

class MdnsClient::Impl {
public:
    using ExchangeResult = Result<ldns_pkt_ptr, DnsError>;

    explicit Impl(Config config)
            : m_config(std::move(config)) {
        if (m_config.timeout.count() <= 0) {
            m_config.timeout = DEFAULT_TIMEOUT;
        }
        if (m_config.idle_timeout.count() <= 0) {
            m_config.idle_timeout = DEFAULT_IDLE_TIMEOUT;
        }
    }

    ~Impl() {
        m_shutting_down = true;
        for (auto it = m_requests.begin(); it != m_requests.end();) {
            auto next = std::next(it);
            it->second.error = make_error(DnsError::AE_SHUTTING_DOWN);
            complete(it->second);
            it = next;
        }
        close_sockets();
    }

    coro::Task<ExchangeResult> exchange(const ldns_pkt *request);

private:
    /**
     * A UDP socket owned by the client: either a query socket (one per address family, or one
     * per interface for IPv6 multicast) or a multicast listener bound to the mDNS port.
     */
    struct SocketState {
        Impl *parent = nullptr;
        UvPtr<uv_udp_t> handle;
        std::vector<SocketAddress> targets;
        std::array<char, MAX_PACKET_SIZE> recv_buffer{};
    };

    struct Request {
        uint64_t id = 0;
        Impl *parent = nullptr;
        ldns_pkt_ptr request;
        std::string qname;
        ldns_rr_type qtype = LDNS_RR_TYPE_A;
        Uint8Vector query;
        Uint8Vector retransmit_query; ///< Same query without the unicast-response bit.
        LdnsRrListPtr answers{ldns_rr_list_new()};
        LdnsRrListPtr additional{ldns_rr_list_new()};
        ldns_pkt_ptr reply;
        Error<DnsError> error;
        int attempt = 0;
        bool answered = false;
        UvPtr<uv_timer_t> retransmit_timer;
        UvPtr<uv_timer_t> deadline_timer;
        std::coroutine_handle<> continuation;
    };

    bool start(Request &req);
    bool build_query(Request &req);
    void send_query(Request &req);
    void process_response(const uint8_t *data, size_t len);
    bool match_response(Request &req, const ldns_pkt *response);
    void complete(Request &req);
    ldns_pkt_ptr make_reply(const Request &req);

    bool open_sockets();
    void close_sockets();
    std::unique_ptr<SocketState> create_socket(int family, std::vector<SocketAddress> targets, bool listener,
            uint32_t multicast_interface_index, const std::string &multicast_interface);
    bool configure_fd(uv_udp_t *handle, const SocketAddress &peer);
    void schedule_idle_close();

    static void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
    static void on_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const sockaddr *addr, unsigned flags);
    static void on_retransmit(uv_timer_t *handle);
    static void on_deadline(uv_timer_t *handle);
    static void on_idle(uv_timer_t *handle);

    Config m_config;
    uint64_t m_next_request_id = 0;
    std::map<uint64_t, Request> m_requests;
    std::vector<std::unique_ptr<SocketState>> m_query_sockets;
    std::vector<std::unique_ptr<SocketState>> m_listeners;
    UvPtr<uv_timer_t> m_idle_timer;
    bool m_sockets_open = false;
    bool m_multicast_enabled = false;
    bool m_shutting_down = false;
};

bool MdnsClient::Impl::start(Request &req) {
    if (m_config.loop == nullptr) {
        req.error = make_error(DnsError::AE_INTERNAL_ERROR, "Event loop is not set");
        return true;
    }
    if (!open_sockets()) {
        req.error = make_error(DnsError::AE_SOCKET_ERROR, "Failed to create mDNS sockets");
        return true;
    }
    if (!build_query(req)) {
        return true;
    }

    req.deadline_timer = Uv<uv_timer_t>::create_with_parent(&req);
    if (0 != uv_timer_init(m_config.loop->handle(), req.deadline_timer->raw())) {
        req.deadline_timer->mark_uninit();
        req.error = make_error(DnsError::AE_INTERNAL_ERROR, "Failed to init mDNS deadline timer");
        return true;
    }
    if (0 != uv_timer_start(req.deadline_timer->raw(), on_deadline, m_config.timeout.count(), 0)) {
        req.error = make_error(DnsError::AE_INTERNAL_ERROR, "Failed to start mDNS deadline timer");
        return true;
    }

    req.retransmit_timer = Uv<uv_timer_t>::create_with_parent(&req);
    if (0 != uv_timer_init(m_config.loop->handle(), req.retransmit_timer->raw())) {
        req.retransmit_timer->mark_uninit();
        req.error = make_error(DnsError::AE_INTERNAL_ERROR, "Failed to init mDNS retransmit timer");
        return true;
    }
    if (0 != uv_timer_start(req.retransmit_timer->raw(), on_retransmit, RETRANSMIT_INTERVAL.count(), 0)) {
        req.error = make_error(DnsError::AE_INTERNAL_ERROR, "Failed to start mDNS retransmit timer");
        return true;
    }

    // A request is pending: keep the listener sockets and the multicast lock alive.
    if (m_idle_timer) {
        uv_timer_stop(m_idle_timer->raw());
    }

    send_query(req);
    return false;
}

bool MdnsClient::Impl::build_query(Request &req) {
    std::string error;
    if (!build_mdns_query(req.request.get(), /*unicast_response=*/true, req.query, error)
            || !build_mdns_query(req.request.get(), /*unicast_response=*/false, req.retransmit_query, error)) {
        req.error = make_error(DnsError::AE_ENCODE_ERROR, error);
        return false;
    }
    return true;
}

void MdnsClient::Impl::send_query(Request &req) {
    // The unicast-response bit is only set on the initial transmission (RFC 6762 §5.4).
    Uint8Vector &query = req.attempt == 0 ? req.query : req.retransmit_query;
    for (const auto &state : m_query_sockets) {
        for (const SocketAddress &target : state->targets) {
            uv_buf_t buffer =
                    uv_buf_init(reinterpret_cast<char *>(query.data()), static_cast<unsigned int>(query.size()));
            int rc = uv_udp_try_send(state->handle->raw(), &buffer, 1, target.c_sockaddr());
            if (rc < 0) {
                dbglog(g_log, "Failed to send mDNS query to {}: {}", target.str(), uv_strerror(rc));
            }
        }
    }
}

void MdnsClient::Impl::process_response(const uint8_t *data, size_t len) {
    ldns_pkt *pkt = nullptr;
    if (ldns_wire2pkt(&pkt, data, len) != LDNS_STATUS_OK || pkt == nullptr) {
        return;
    }
    ldns_pkt_ptr response{pkt};

    std::vector<uint64_t> matched;
    for (auto &[id, req] : m_requests) {
        if (req.answered) {
            continue;
        }
        if (match_response(req, response.get())) {
            req.answered = true;
            matched.push_back(id);
        }
    }
    for (uint64_t id : matched) {
        if (auto it = m_requests.find(id); it != m_requests.end()) {
            complete(it->second);
        }
    }
}

bool MdnsClient::Impl::match_response(Request &req, const ldns_pkt *response) {
    // A record answers the question if its owner matches and its type is the requested type;
    // CNAME aliases and NSEC negative responses also answer it (RFC 6762 §6, §6.1).
    const auto type_matches = [&req](const ldns_rr *rr) {
        const ldns_rr_type type = ldns_rr_get_type(rr);
        return req.qtype == LDNS_RR_TYPE_ANY || type == req.qtype || type == LDNS_RR_TYPE_CNAME
                || type == LDNS_RR_TYPE_NSEC;
    };

    const ldns_rr_list *answer = ldns_pkt_answer(response);
    const ldns_rr_list *additional = ldns_pkt_additional(response);

    // mDNS responses often have an empty question section, so match on the answer records.
    bool matches = false;
    for (size_t i = 0, count = ldns_rr_list_rr_count(answer); i < count && !matches; i++) {
        const ldns_rr *rr = ldns_rr_list_rr(answer, i);
        matches = utils::iequals(rr_owner(rr), req.qname) && type_matches(rr);
    }
    if (!matches) {
        return false;
    }

    // Follow CNAME chains: records of the requested type owned by an alias target are part of
    // the answer section as well.
    std::vector<std::string> related_owners{req.qname};
    for (size_t round = 0; round < 4; round++) { // chains are short; bound the walk
        bool extended = false;
        for (const ldns_rr_list *section : {answer, additional}) {
            for (size_t i = 0, count = ldns_rr_list_rr_count(section); i < count; i++) {
                const ldns_rr *rr = ldns_rr_list_rr(section, i);
                if (!is_related_owner(related_owners, rr_owner(rr))) {
                    continue;
                }
                std::string target = cname_target(rr);
                if (!target.empty() && !is_related_owner(related_owners, target)) {
                    related_owners.push_back(std::move(target));
                    extended = true;
                }
            }
        }
        if (!extended) {
            break;
        }
    }

    // Records of the requested type (or alias/negative records) form the answer section;
    // everything else (e.g. SRV/TXT/A records of a service instance for a PTR query) goes to
    // the additional section.
    for (const ldns_rr_list *section : {answer, additional}) {
        for (size_t i = 0, count = ldns_rr_list_rr_count(section); i < count; i++) {
            const ldns_rr *rr = ldns_rr_list_rr(section, i);
            ldns_rr *copy = ldns_rr_clone(rr);
            if (is_related_owner(related_owners, rr_owner(rr)) && type_matches(rr)) {
                ldns_rr_list_push_rr(req.answers.get(), copy);
            } else {
                ldns_rr_list_push_rr(req.additional.get(), copy);
            }
        }
    }
    return true;
}

void MdnsClient::Impl::complete(Request &req) {
    if (req.retransmit_timer) {
        uv_timer_stop(req.retransmit_timer->raw());
    }
    if (req.deadline_timer) {
        uv_timer_stop(req.deadline_timer->raw());
    }

    if (!req.error) {
        req.reply = make_reply(req);
    }

    // Resuming the awaiting coroutine destroys the request (it extracts the entry from
    // `m_requests`), so this must be the last use of `req`.
    if (req.continuation) {
        std::exchange(req.continuation, nullptr).resume();
    } else {
        m_requests.erase(req.id);
    }

    if (m_requests.empty() && !m_shutting_down) {
        schedule_idle_close();
    }
}

ldns_pkt_ptr MdnsClient::Impl::make_reply(const Request &req) {
    ldns_pkt_ptr reply{ldns_pkt_clone(req.request.get())};
    ldns_pkt_set_qr(reply.get(), true);
    ldns_pkt_set_aa(reply.get(), false);
    ldns_pkt_set_rd(reply.get(), true);
    ldns_pkt_set_ra(reply.get(), true);
    ldns_pkt_set_ad(reply.get(), false);
    ldns_pkt_set_cd(reply.get(), false);

    const size_t answer_count = ldns_rr_list_rr_count(req.answers.get());
    if (answer_count > 0) {
        ldns_pkt_set_rcode(reply.get(), LDNS_RCODE_NOERROR);
        // ldns_pkt_set_answer()/set_additional() do not free the lists they replace.
        ldns_rr_list_deep_free(ldns_pkt_answer(reply.get()));
        ldns_pkt_set_answer(reply.get(), ldns_rr_list_clone(req.answers.get()));
        ldns_pkt_set_ancount(reply.get(), static_cast<uint16_t>(answer_count));

        const size_t additional_count = ldns_rr_list_rr_count(req.additional.get());
        if (additional_count > 0) {
            ldns_rr_list_deep_free(ldns_pkt_additional(reply.get()));
            ldns_pkt_set_additional(reply.get(), ldns_rr_list_clone(req.additional.get()));
            ldns_pkt_set_arcount(reply.get(), static_cast<uint16_t>(additional_count));
        }
    } else {
        // A responder that owns the name answers negative queries with an NSEC record (handled
        // above); no response at all means the name could not be resolved. This mirrors the
        // Android system resolver reporting "no such name" for `.local` queries.
        ldns_pkt_set_rcode(reply.get(), LDNS_RCODE_NXDOMAIN);
        if (ldns_rr *soa = create_negative_soa(req.request.get())) {
            ldns_pkt_push_rr(reply.get(), LDNS_SECTION_AUTHORITY, soa);
        }
    }
    return reply;
}

bool MdnsClient::Impl::open_sockets() {
    if (m_sockets_open) {
        return true;
    }

    const bool multicast_mode = m_config.servers.empty();
    bool has_query_socket = false;

    if (multicast_mode) {
        if (m_config.enable_ipv4) {
            auto state = create_socket(AF_INET, {SocketAddress(MDNS_GROUP_V4, m_config.multicast_port)}, false, 0, {});
            if (state != nullptr) {
                m_query_sockets.push_back(std::move(state));
                has_query_socket = true;
            }
        }
        if (m_config.enable_ipv6) {
            for (const MdnsInterface &iface : find_ipv6_interfaces()) {
                SocketAddress target = make_scoped_address(MDNS_GROUP_V6, m_config.multicast_port, iface.index);
                auto state = create_socket(AF_INET6, {target}, false, iface.index, multicast_interface_arg(iface));
                if (state != nullptr) {
                    m_query_sockets.push_back(std::move(state));
                    has_query_socket = true;
                }
            }
        }
    } else {
        std::vector<SocketAddress> v4;
        std::vector<SocketAddress> v6;
        for (const SocketAddress &server : m_config.servers) {
            if (server.is_ipv4()) {
                v4.push_back(server);
            } else if (server.is_ipv6()) {
                v6.push_back(server);
            }
        }
        if (!v4.empty()) {
            auto state = create_socket(AF_INET, std::move(v4), false, 0, {});
            if (state != nullptr) {
                m_query_sockets.push_back(std::move(state));
                has_query_socket = true;
            }
        }
        if (!v6.empty()) {
            auto state = create_socket(AF_INET6, std::move(v6), false, 0, {});
            if (state != nullptr) {
                m_query_sockets.push_back(std::move(state));
                has_query_socket = true;
            }
        }
    }

    if (!has_query_socket) {
        warnlog(g_log, "Failed to create any mDNS query socket");
        close_sockets();
        return false;
    }

    // Multicast listeners are best effort: if the group cannot be joined, the client still
    // works through unicast QU responses.
    if (multicast_mode) {
        const std::vector<MdnsInterface> ipv6_ifs =
                m_config.enable_ipv6 ? find_ipv6_interfaces() : std::vector<MdnsInterface>{};

        if (m_config.enable_ipv4) {
            auto listener = create_socket(AF_INET, {}, true, 0, {});
            if (listener != nullptr) {
                int rc = uv_udp_set_membership(listener->handle->raw(), MDNS_GROUP_V4, nullptr, UV_JOIN_GROUP);
                if (rc == 0) {
                    m_listeners.push_back(std::move(listener));
                } else {
                    warnlog(g_log, "Failed to join the mDNS IPv4 group: {}", uv_strerror(rc));
                }
            }
        }
        for (const MdnsInterface &iface : ipv6_ifs) {
            auto listener = create_socket(AF_INET6, {}, true, iface.index, multicast_interface_arg(iface));
            if (listener == nullptr) {
                continue;
            }
            std::string interface_arg = multicast_interface_arg(iface);
            int rc =
                    uv_udp_set_membership(listener->handle->raw(), MDNS_GROUP_V6, interface_arg.c_str(), UV_JOIN_GROUP);
            if (rc == 0) {
                m_listeners.push_back(std::move(listener));
            } else {
                warnlog(g_log, "Failed to join the mDNS IPv6 group on {}: {}", iface.name, uv_strerror(rc));
            }
        }

        if (!m_listeners.empty()) {
            if (m_config.set_multicast_enabled) {
                m_config.set_multicast_enabled(true);
            }
            m_multicast_enabled = true;
        }
    }

    m_sockets_open = true;
    return true;
}

void MdnsClient::Impl::close_sockets() {
    if (m_idle_timer) {
        uv_timer_stop(m_idle_timer->raw());
    }
    m_query_sockets.clear();
    m_listeners.clear();
    m_sockets_open = false;
    if (m_multicast_enabled) {
        if (m_config.set_multicast_enabled) {
            m_config.set_multicast_enabled(false);
        }
        m_multicast_enabled = false;
    }
}

std::unique_ptr<MdnsClient::Impl::SocketState> MdnsClient::Impl::create_socket(int family,
        std::vector<SocketAddress> targets, bool listener, uint32_t multicast_interface_index,
        const std::string &multicast_interface) {
    auto state = std::make_unique<SocketState>();
    state->parent = this;
    state->targets = std::move(targets);
    state->handle = Uv<uv_udp_t>::create_with_parent(state.get());

    int rc = uv_udp_init_ex(m_config.loop->handle(), state->handle->raw(), family);
    if (rc != 0) {
        state->handle->mark_uninit();
        warnlog(g_log, "Failed to create mDNS socket: {}", uv_strerror(rc));
        return nullptr;
    }

    SocketAddress peer = !state->targets.empty()
            ? state->targets.front()
            : SocketAddress(family == AF_INET ? MDNS_GROUP_V4 : MDNS_GROUP_V6, m_config.multicast_port);
    if (!configure_fd(state->handle->raw(), peer)) {
        return nullptr;
    }

    const uint16_t bind_port = listener ? m_config.multicast_port : 0;
    SocketAddress bind_address =
            family == AF_INET ? SocketAddress("0.0.0.0", bind_port) : SocketAddress("::", bind_port);
    unsigned int bind_flags = 0;
    if (listener) {
        bind_flags |= UV_UDP_REUSEADDR;
        if (family == AF_INET6) {
            // Keep the IPv4 and IPv6 listeners on distinct sockets.
            bind_flags |= UV_UDP_IPV6ONLY;
        }
    }
    rc = uv_udp_bind(state->handle->raw(), bind_address.c_sockaddr(), bind_flags);
    if (rc != 0) {
        warnlog(g_log, "Failed to bind mDNS socket to {}: {}", bind_address.str(), uv_strerror(rc));
        return nullptr;
    }

    // RFC 6762 §11: mDNS messages are sent with the maximum IP TTL. Disable multicast
    // loopback so the client does not receive its own queries.
    (void) uv_udp_set_multicast_ttl(state->handle->raw(), 255);
    (void) uv_udp_set_multicast_loop(state->handle->raw(), 0);
    if (multicast_interface_index != 0
            && 0 != uv_udp_set_multicast_interface(state->handle->raw(), multicast_interface.c_str())) {
        warnlog(g_log, "Failed to select the mDNS multicast interface {}", multicast_interface);
    }

    rc = uv_udp_recv_start(state->handle->raw(), on_alloc, on_recv);
    if (rc != 0) {
        warnlog(g_log, "Failed to start mDNS receive: {}", uv_strerror(rc));
        return nullptr;
    }
    return state;
}

bool MdnsClient::Impl::configure_fd(uv_udp_t *handle, const SocketAddress &peer) {
    evutil_socket_t fd = -1;
    if (0 != uv_fileno(reinterpret_cast<uv_handle_t *>(handle), &fd) || fd < 0) {
        warnlog(g_log, "Failed to get the mDNS socket descriptor");
        return false;
    }

    // Route-loop protection and interface binding, the same as for other upstream sockets.
    if (m_config.socket_factory != nullptr) {
        if (auto err = m_config.socket_factory->prepare_fd(fd, peer, m_config.outbound_interface)) {
            warnlog(g_log, "Failed to prepare the mDNS socket: {}", err->str());
            return false;
        }
    }

    // Platform-specific setup (Android network binding for `system://<interface>`).
    if (m_config.configure_socket) {
        if (auto err = m_config.configure_socket(fd)) {
            warnlog(g_log, "Failed to configure the mDNS socket: {}", err->str());
            return false;
        }
    }
    return true;
}

void MdnsClient::Impl::schedule_idle_close() {
    if (m_listeners.empty() && m_query_sockets.empty()) {
        return;
    }
    if (!m_idle_timer) {
        m_idle_timer = Uv<uv_timer_t>::create_with_parent(this);
        if (0 != uv_timer_init(m_config.loop->handle(), m_idle_timer->raw())) {
            m_idle_timer->mark_uninit();
            m_idle_timer.reset();
            return;
        }
    }
    uv_timer_start(m_idle_timer->raw(), on_idle, m_config.idle_timeout.count(), 0);
}

void MdnsClient::Impl::on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    if (handle->data == nullptr) {
        *buf = uv_buf_init(nullptr, 0);
        return;
    }
    auto *state = static_cast<SocketState *>(Uv<uv_udp_t>::parent_from_data(handle->data));
    if (state == nullptr) {
        *buf = uv_buf_init(nullptr, 0);
        return;
    }
    *buf = uv_buf_init(state->recv_buffer.data(), static_cast<unsigned int>(state->recv_buffer.size()));
}

void MdnsClient::Impl::on_recv(
        uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const sockaddr *addr, unsigned flags) {
    if (handle->data == nullptr) {
        return;
    }
    auto *state = static_cast<SocketState *>(Uv<uv_udp_t>::parent_from_data(handle->data));
    if (state == nullptr || state->parent == nullptr || nread <= 0) {
        return;
    }
    state->parent->process_response(reinterpret_cast<const uint8_t *>(buf->base), static_cast<size_t>(nread));
}

void MdnsClient::Impl::on_retransmit(uv_timer_t *handle) {
    if (handle->data == nullptr) {
        return;
    }
    auto *req = static_cast<Request *>(Uv<uv_timer_t>::parent_from_data(handle->data));
    if (req == nullptr || req->answered) {
        return;
    }
    req->attempt++;
    req->parent->send_query(*req);
    // RFC 6762 §5.2: retransmission intervals double (1s, 2s, 4s, ...).
    uint64_t delay = static_cast<uint64_t>(RETRANSMIT_INTERVAL.count()) << std::min(req->attempt, 5);
    if (0 != uv_timer_start(handle, on_retransmit, delay, 0)) {
        dbglog(g_log, "Failed to reschedule mDNS retransmission");
    }
}

void MdnsClient::Impl::on_deadline(uv_timer_t *handle) {
    if (handle->data == nullptr) {
        return;
    }
    auto *req = static_cast<Request *>(Uv<uv_timer_t>::parent_from_data(handle->data));
    if (req == nullptr || req->answered) {
        return;
    }
    req->parent->complete(*req);
}

void MdnsClient::Impl::on_idle(uv_timer_t *handle) {
    if (handle->data == nullptr) {
        return;
    }
    auto *impl = static_cast<Impl *>(Uv<uv_timer_t>::parent_from_data(handle->data));
    if (impl == nullptr || !impl->m_requests.empty()) {
        return;
    }
    impl->close_sockets();
}

coro::Task<MdnsClient::Impl::ExchangeResult> MdnsClient::Impl::exchange(const ldns_pkt *request) {
    uint64_t id = m_next_request_id++;
    Request &req = m_requests[id];
    req.id = id;
    req.parent = this;
    req.request.reset(ldns_pkt_clone(request));

    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    if (question != nullptr) {
        AllocatedPtr<char> qname{ldns_rdf2str(ldns_rr_owner(question))};
        if (qname != nullptr) {
            req.qname = qname.get();
        }
        req.qtype = ldns_rr_get_type(question);
    }

    struct Awaitable {
        Request *req;

        bool await_ready() {
            return req->parent->start(*req);
        }

        void await_suspend(std::coroutine_handle<> continuation) {
            req->continuation = continuation;
        }

        ExchangeResult await_resume() {
            auto node = req->parent->m_requests.extract(req->id);
            Request &completed = node.mapped();
            if (completed.error) {
                return std::move(completed.error);
            }
            return std::move(completed.reply);
        }
    };

    co_return co_await Awaitable{.req = &req};
}

MdnsClient::MdnsClient(Config config)
        : m_pimpl(std::make_unique<Impl>(std::move(config))) {
}

MdnsClient::~MdnsClient() = default;

std::unique_ptr<MdnsClient> MdnsClient::create(Config config) {
    return std::unique_ptr<MdnsClient>(new MdnsClient(std::move(config)));
}

bool MdnsClient::is_local_name(std::string_view name) {
    if (name.ends_with('.')) {
        name.remove_suffix(1);
    }
    const size_t dot = name.rfind('.');
    const std::string_view last_label = dot == std::string_view::npos ? name : name.substr(dot + 1);
    return utils::iequals(last_label, "local");
}

coro::Task<Result<ldns_pkt_ptr, DnsError>> MdnsClient::exchange(const ldns_pkt *request) {
    co_return co_await m_pimpl->exchange(request);
}

} // namespace ag::dns
