#include "dns_framed.h"
#include <vector>
#include <mutex>
#include <list>
#include <ldns/wire2host.h>
#include <event2/buffer.h>
#include <ag_socket_address.h>
#include <ag_logger.h>
#include <ag_utils.h>

using namespace std::chrono;

#define tracelog_ip(l_, fmt_, ...) tracelog(l_, "[{}] " fmt_, this->m_socket_address.str(), ##__VA_ARGS__)

int ag::dns_framed_connection::write(ag::uint8_view buf) {
    tracelog_ip(m_log, "{} len={}", __func__, buf.size());
    dns_framed_connection_ptr ptr = shared_from_this();
    if (buf.size() < 2) {
        tracelog_ip(m_log, "{} returned -1", __func__);
        return -1;
    }
    uint16_t id = *(uint16_t *) buf.data();
    {
        std::scoped_lock l(m_mutex);

        using evbuffer_ptr = std::unique_ptr<evbuffer, ag::ftor<&evbuffer_free>>;
        evbuffer_ptr packet_buf{evbuffer_new()};

        uint16_t pkt_len_net = htons((uint16_t) buf.size());
        evbuffer_add(&*packet_buf, &pkt_len_net, 2);
        evbuffer_add(&*packet_buf, buf.data(), buf.size());

        bufferevent_write_buffer(&*m_bev, &*packet_buf);

        m_requests[id] = std::nullopt;
    }
    tracelog_ip(m_log, "{} returned {}", __func__, id);
    return id;
}

ag::dns_framed_connection::dns_framed_connection(dns_framed_pool *pool, bufferevent *bev, const socket_address &address)
        : m_log(ag::create_logger(__func__)), m_pool(pool), m_bev(bev), m_socket_address(address) {
    bufferevent_setcb(&*m_bev, [](bufferevent *, void *arg) {
        auto conn = (ag::dns_framed_connection *) arg;
        conn->on_read();
    }, nullptr, [](bufferevent *, short what, void *arg) {
        auto conn = (ag::dns_framed_connection *) arg;
        conn->on_event(what);
    }, this);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

ag::dns_framed_connection::~dns_framed_connection() {
}

ag::dns_framed_connection_ptr ag::dns_framed_connection::create(dns_framed_pool *pool, bufferevent *bev, const socket_address &address) {
    return ag::dns_framed_connection_ptr{new dns_framed_connection(pool, bev, address), [](dns_framed_connection *conn){
        if (conn->m_bev) {
            event_base_once(bufferevent_get_base(conn->m_bev.get()), -1, EV_TIMEOUT,
                            [](evutil_socket_t, short, void *ptr) {
                                delete (dns_framed_connection *) ptr;
                            }, conn, nullptr);
        } else {
            delete conn;
        }
    }};
}

void ag::dns_framed_connection::on_read() {
    tracelog_ip(m_log, "{}", __func__);
    dns_framed_connection_ptr ptr = shared_from_this();
    auto *input = bufferevent_get_input(&*m_bev);
    for (;;) {
        if (evbuffer_get_length(input) < 2) {
            break;
        }
        uint16_t length;
        evbuffer_copyout(input, &length, 2);
        length = ntohs(length);
        if (length < 2) {
            break;
        }
        if (evbuffer_get_length(input) < 2 + length) {
            break;
        }
        evbuffer_drain(input, 2);
        std::vector<uint8_t> buf;
        buf.resize(length);
        evbuffer_remove(input, buf.data(), buf.size());
        int id = *(uint16_t *)buf.data();
        {
            std::unique_lock l(m_mutex);
            if (m_requests.count(id)) {
                m_requests.at(id) = {std::move(buf), std::nullopt};
            }
            m_cond.notify_all();
        }
    }
    tracelog_ip(m_log, "{} finished", __func__);
}

void ag::dns_framed_connection::on_event(int what) {
    tracelog_ip(m_log, "{}", __func__);
    dns_framed_connection_ptr ptr = shared_from_this();
    if (what & BEV_EVENT_CONNECTED) {
        tracelog_ip(m_log, "{} connected", __func__);
        m_pool->add_connected(shared_from_this());
    }
    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        if (what & BEV_EVENT_EOF) {
            tracelog_ip(m_log, "{} eof", __func__);
        } else {
            tracelog_ip(m_log, "{} error {}", __func__, evutil_socket_error_to_string(evutil_socket_geterror(bufferevent_getfd(m_bev.get()))));
        }
        m_pool->remove_from_all(shared_from_this());
        std::unique_lock l(m_mutex);
        for (auto &entry : m_requests) {
            std::string error = (what & BEV_EVENT_EOF) ? std::string(UNEXPECTED_EOF) :
                                evutil_socket_error_to_string(evutil_socket_geterror(bufferevent_getfd(m_bev.get())));
            // Set result
            entry.second = {std::vector<uint8_t>{}, {std::move(error)}};
        }
        m_cond.notify_all();
    }
    tracelog_ip(m_log, "{} finished", __func__);
}

ag::connection::result ag::dns_framed_connection::read(int request_id, std::chrono::milliseconds timeout) {
    dns_framed_connection_ptr ptr = shared_from_this();
    std::unique_lock l(m_mutex);

    bool request_replied = m_cond.wait_until(l, std::chrono::steady_clock::now() + timeout, [&]{
        const auto it = m_requests.find(request_id);
        return it != m_requests.end() && (*it).second.has_value();
    });

    if (!request_replied) {
        l.unlock();
        // Request timed out, don't accept new connections on this endpoint
        m_pool->remove_from_all(shared_from_this());
        l.lock();
        return {{}, {"Timed out"}};
    }
    auto result_node = m_requests.extract(request_id);
    return result_node.mapped().value();
}

const ag::socket_address &ag::dns_framed_connection::address() const {
    return m_socket_address;
}

void ag::dns_framed_pool::add_connected(const dns_framed_connection_ptr &ptr) {
    tracelog(ptr->m_log, "[{}] {}", ptr->m_socket_address.str(), __func__);

    std::scoped_lock l(m_mutex);
    m_pending_connections.erase(ptr);
    m_connections.push_back(ptr);
}

void ag::dns_framed_pool::remove_from_all(const dns_framed_connection_ptr &ptr) {
    tracelog(ptr->m_log, "[{}] {}", ptr->m_socket_address.str(), __func__);

    std::scoped_lock l(m_mutex);
    m_pending_connections.erase(ptr);
    m_connections.remove(ptr);
}

void ag::dns_framed_pool::add_pending_connection(const ag::dns_framed_connection_ptr &ptr) {
    tracelog(ptr->m_log, "[{}] {}", ptr->m_socket_address.str(), __func__);

    m_pending_connections.insert(ptr);
}

std::pair<std::vector<uint8_t>, ag::err_string> ag::dns_framed_pool::perform_request_inner(uint8_view buf,
        milliseconds timeout) {
    auto[conn, elapsed, err] = get();
    if (!conn) {
        return { {}, std::move(err) };
    }

    int id = conn->write(buf);
    timeout -= duration_cast<milliseconds>(elapsed);
    if (timeout < milliseconds(0)) {
        return { {}, AG_FMT("DNS server name resolving took too much time: {}", elapsed) };
    }

    return conn->read(id, timeout);
}

std::pair<std::vector<uint8_t>, ag::err_string> ag::dns_framed_pool::perform_request(uint8_view buf,
        milliseconds timeout) {
    utils::timer timer;
    std::pair<std::vector<uint8_t>, err_string> result = perform_request_inner(buf, timeout);
    // try one more time in case of the server closed the connection before we got the response
    // https://github.com/AdguardTeam/DnsLibs/issues/24
    if (result.second.has_value() && result.second.value() == dns_framed_connection::UNEXPECTED_EOF) {
        timeout -= timer.elapsed<milliseconds>();
        if (timeout < milliseconds(0)) {
            result.second.emplace("Timed out");
        } else {
            result = perform_request_inner(buf, timeout);
        }
    }
    return result;
}
