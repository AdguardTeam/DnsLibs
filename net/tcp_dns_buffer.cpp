#include "dns/net/tcp_dns_buffer.h"
#include <cassert>
#include <cstring>

#ifndef _WIN32
#include <netinet/in.h>
#else
#include <Winsock2.h>
#endif

namespace ag::dns {

static constexpr size_t PACKET_LENGTH_LENGTH = 2;
static constexpr size_t BUFFER_MIN_CAPACITY = 512;

static size_t ntoh_length(const uint8_t *data) {
    uint16_t net_length;
    std::memcpy(&net_length, data, PACKET_LENGTH_LENGTH);
    return ntohs(net_length);
}

Uint8View TcpDnsBuffer::store(Uint8View data) {
    if (!m_total_length.has_value()) {
        if (m_buffer.empty() && data.size() >= PACKET_LENGTH_LENGTH) {
            m_total_length = ntoh_length(data.data());
            data.remove_prefix(PACKET_LENGTH_LENGTH);
        } else if (m_buffer.size() < PACKET_LENGTH_LENGTH) {
            m_buffer.reserve(BUFFER_MIN_CAPACITY);
            size_t to_insert = std::min(data.size(), PACKET_LENGTH_LENGTH);
            m_buffer.insert(m_buffer.end(), data.begin(), std::next(data.begin(), ssize_t(to_insert)));
            if (m_buffer.size() >= PACKET_LENGTH_LENGTH) {
                m_total_length = ntoh_length(m_buffer.data());
                m_buffer.erase(m_buffer.begin(), std::next(m_buffer.begin(), PACKET_LENGTH_LENGTH));
                data.remove_prefix(to_insert);
            }
        }

        if (m_total_length.has_value()) {
            m_buffer.reserve(std::max(m_total_length.value(), BUFFER_MIN_CAPACITY));
        } else {
            return {};
        }
    }

    size_t to_insert = std::min(data.size(), m_total_length.value() - m_buffer.size());
    m_buffer.insert(m_buffer.end(), data.begin(), std::next(data.begin(), (ssize_t) to_insert));

    assert(m_buffer.size() <= m_total_length.value());

    data.remove_prefix(to_insert);
    return data;
}

std::optional<Uint8Vector> TcpDnsBuffer::extract_packet() {
    if (!m_total_length.has_value() || m_buffer.size() < m_total_length.value()) {
        return std::nullopt;
    }

    m_total_length.reset();
    return std::exchange(m_buffer, {});
}

} // namespace ag::dns
