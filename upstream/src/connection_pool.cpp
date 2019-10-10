#include "connection_pool.h"
#include <vector>
#include <mutex>
#include <ldns/wire2host.h>
#include <event2/buffer.h>
#include <socket_address.h>

int ag::dns_framed_connection::write(vector_view buf) {
    dns_framed_connection_ptr ptr = shared_from_this();
    if (buf.size() < 2) {
        return -1;
    }
    fprintf(stderr, "%s:%d\n", __func__, __LINE__);
    uint16_t id = *(uint16_t *) buf.data();
    {
        std::scoped_lock l(m_mutex);

        using evbuffer_ptr = std::unique_ptr<evbuffer, decltype(&evbuffer_free)>;
        evbuffer_ptr packet_buf = {evbuffer_new(), &evbuffer_free};

        uint16_t pkt_len_net = htons((uint16_t) buf.size());
        evbuffer_add(&*packet_buf, &pkt_len_net, 2);
        evbuffer_add(&*packet_buf, buf.data(), buf.size());

        bufferevent_write_buffer(m_bev, &*packet_buf);

        m_requests[id] = std::nullopt;
    }
    return id;
}

ag::dns_framed_connection::dns_framed_connection(tcp_connection_pool *pool, bufferevent *bev, const socket_address &address)
        : m_pool(pool), m_bev(bev), m_socket_address(address) {
    bufferevent_setcb(m_bev, [](bufferevent *, void *arg) {
        auto conn = (ag::dns_framed_connection *) arg;
        conn->on_read();
    }, [](bufferevent *, void *arg) {
        auto conn = (ag::dns_framed_connection *) arg;
        fprintf(stderr, "on_write\n");
    }, [](bufferevent *, short what, void *arg) {
        auto conn = (ag::dns_framed_connection *) arg;
        conn->on_event(what);
    }, this);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

ag::dns_framed_connection::~dns_framed_connection() {
    bufferevent_free(m_bev);
}

ag::dns_framed_connection_ptr ag::dns_framed_connection::create(tcp_connection_pool *pool, bufferevent *bev, const socket_address &address) {
    return ag::dns_framed_connection_ptr{new dns_framed_connection(pool, bev, address)};
}

void ag::dns_framed_connection::on_read() {
    dns_framed_connection_ptr ptr = shared_from_this();
    fprintf(stderr, "%s:%d\n", __func__, __LINE__);
    auto *input = bufferevent_get_input(m_bev);
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
    fprintf(stderr, "%s:%d\n", __func__, __LINE__);
}

void ag::dns_framed_connection::on_event(int what) {
    dns_framed_connection_ptr ptr = shared_from_this();
    fprintf(stderr, "%s:%d %d\n", __func__, __LINE__, what);
    if (what & BEV_EVENT_CONNECTED) {
        m_pool->add(shared_from_this());
    }
    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        m_pool->remove(shared_from_this());
        std::unique_lock l(m_mutex);
        for (auto &[_, result] : m_requests) {
            std::string error = (what & BEV_EVENT_EOF) ? "Unexpected EOF" :
                    evutil_socket_error_to_string(evutil_socket_geterror(bufferevent_getfd(m_bev)));
            result = {std::vector<uint8_t>{}, {std::move(error)}};
        }
        m_cond.notify_all();
    }
    fprintf(stderr, "%s:%d\n", __func__, __LINE__);
}

ag::connection::result ag::dns_framed_connection::read(int request_id, std::chrono::milliseconds timeout) {
    dns_framed_connection_ptr ptr = shared_from_this();
    std::unique_lock l(m_mutex);

    bool request_replied = m_cond.wait_until(l, std::chrono::steady_clock::now() + timeout, [&]{
        return m_requests.at(request_id).has_value();
    });

    if (!request_replied) {
        // Request timed out, don't accept new connections on this endpoint
        m_pool->remove(shared_from_this());
        return {{}, {"Timed out"}};
    }
    auto result_node = m_requests.extract(request_id);
    return result_node.mapped().value();
}

const ag::socket_address &ag::dns_framed_connection::address() const {
    return m_socket_address;
}

void ag::tcp_connection_pool::add(const dns_framed_connection_ptr &ptr) {
    m_pending_connections.erase(ptr);
    m_connections.erase(ptr->address());
    m_connections[ptr->address()] = ptr;
}

void ag::tcp_connection_pool::remove(const dns_framed_connection_ptr &ptr) {
    m_pending_connections.erase(ptr);
    m_connections.erase(ptr->address());
}
