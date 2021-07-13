#include <ag_utils.h>
#include <ag_net_utils.h>
#include "upstream_plain.h"
#include <ag_blocking_socket.h>

#define tracelog_id(l_, pkt_, fmt_, ...) tracelog((l_), "[{}] " fmt_, ldns_pkt_id(pkt_), ##__VA_ARGS__)

using std::chrono::milliseconds;
using std::chrono::duration_cast;

ag::tcp_pool::tcp_pool(event_loop_ptr loop, const socket_address &address, plain_dns *upstream)
    : dns_framed_pool(std::move(loop), upstream)
    , m_address(address)
{}

static ag::socket_address prepare_address(const std::string &address_string) {
    auto address = ag::utils::str_to_socket_address(address_string);
    if (address.port() == 0) {
        return ag::socket_address(address.addr(), ag::plain_dns::DEFAULT_PORT);
    }
    return address;
}

ag::plain_dns::plain_dns(const upstream_options &opts, const upstream_factory_config &config)
        : upstream(opts, config)
        , m_log(ag::create_logger(AG_FMT("Plain upstream ({})", opts.address)))
        , m_prefer_tcp(utils::starts_with(opts.address, TCP_SCHEME))
        , m_pool(event_loop::create(),
                 prepare_address(m_prefer_tcp
                                 ? opts.address.substr(TCP_SCHEME.length())
                                 : opts.address), this) {}

ag::err_string ag::plain_dns::init() {
    if (!m_pool.address().valid()) {
        return AG_FMT("Passed server address is not valid: {}", this->m_options.address);
    }

    return std::nullopt;
}

ag::plain_dns::exchange_result ag::plain_dns::exchange(ldns_pkt *request_pkt, const dns_message_info *info) {
    ldns_buffer_ptr buffer{ldns_buffer_new(REQUEST_BUFFER_INITIAL_CAPACITY)};
    ldns_status status = ldns_pkt2buffer_wire(&*buffer, request_pkt);
    if (status != LDNS_STATUS_OK) {
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }

    ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request_pkt), 0);
    allocated_ptr<char> domain;
    if (question) {
        domain = allocated_ptr<char>(ldns_rdf2str(ldns_rr_owner(question)));
        tracelog_id(m_log, request_pkt, "Querying for a domain: {}", domain.get());
    }

    utils::timer timer;
    milliseconds timeout = m_options.timeout;

    if (!m_prefer_tcp && !(info && info->proto == utils::TP_TCP)) {
        blocking_socket socket(this->make_socket(utils::TP_UDP));
        if (!socket) {
            return { nullptr, "Can't initialize blocking socket wrapper"};
        }

        if (auto e = socket.connect({ m_pool.address(), timeout }); e.has_value()) {
            return { nullptr,
                    (e->code == utils::AG_ETIMEDOUT) // To cancel second retry of exchange
                            ? std::string(TIMEOUT_STR) : std::move(e->description) };
        }

        timeout -= timer.elapsed<decltype(timeout)>();
        if (timeout.count() <= 0) {
            return { nullptr, std::string(TIMEOUT_STR) };
        }
        timer.reset();

        if (auto e = socket.send_dns_packet({ (uint8_t *)ldns_buffer_begin(buffer.get()), ldns_buffer_position(buffer.get()) });
                e.has_value()) {
            return { nullptr, std::move(e->description) };
        }

        auto r = socket.receive_dns_packet(timeout);
        if (auto *e = std::get_if<socket::error>(&r); e != nullptr) {
            return { nullptr,
                    (e->code == utils::AG_ETIMEDOUT) // To cancel second retry of exchange
                    ? std::string(TIMEOUT_STR) : std::move(e->description) };
        }

        auto &reply = std::get<std::vector<uint8_t>>(r);
        ldns_pkt *reply_pkt = nullptr;
        status = ldns_wire2pkt(&reply_pkt, reply.data(), reply.size());
        if (status != LDNS_STATUS_OK) {
            return {nullptr, ldns_get_errorstr_by_id(status)};
        }
        // If not truncated, return result. Otherwise, try TCP.
        if (!ldns_pkt_tc(reply_pkt)) {
            return {ldns_pkt_ptr(reply_pkt), std::nullopt};
        }
        ldns_pkt_free(reply_pkt);
    }

    timeout -= timer.elapsed<decltype(timeout)>();
    if (timeout.count() <= 0) {
        return { nullptr, std::string(TIMEOUT_STR) };
    }

    // TCP request
    ag::uint8_view buf{ ldns_buffer_begin(buffer.get()), ldns_buffer_position(buffer.get()) };
    tracelog_id(m_log, request_pkt, "Sending TCP request for a domain: {}", domain ? domain.get() : "(unknown)");
    connection::read_result result = m_pool.perform_request(buf, timeout);
    if (result.error.has_value()) {
        return { nullptr, std::move(result.error) };
    }

    const std::vector<uint8_t> &reply = result.reply;
    ldns_pkt *reply_pkt = nullptr;
    status = ldns_wire2pkt(&reply_pkt, reply.data(), reply.size());
    if (status != LDNS_STATUS_OK) {
        return {nullptr, ldns_get_errorstr_by_id(status)};
    }
    return {ldns_pkt_ptr(reply_pkt), std::nullopt};
}

ag::connection_pool::get_result ag::tcp_pool::get() {
    std::scoped_lock l(m_mutex);
    if (!m_connections.empty()) {
        return {*m_connections.begin(), std::chrono::seconds(0), std::nullopt};
    }
    return create();
}

ag::connection_pool::get_result ag::tcp_pool::create() {
    connection_ptr connection = create_connection(nullptr, m_address);
    add_pending_connection(connection);
    return { std::move(connection), std::chrono::seconds(0), std::nullopt };
}

const ag::socket_address &ag::tcp_pool::address() const {
    return m_address;
}
