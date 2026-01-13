#pragma once

#include "common/defs.h"

namespace ag::dns {

/**
 * TCP DNS payload parser - handles length-prefixed DNS messages over TCP
 * 
 * TCP DNS messages are prefixed with a 2-byte length field (network byte order)
 * followed by the DNS message payload.
 */
class TcpDnsPayloadParser {
private:
    enum class State { RD_SIZE, RD_PAYLOAD };
    State m_state = State::RD_SIZE;
    uint16_t m_size = 0;
    Uint8Vector m_data;

public:
    TcpDnsPayloadParser() = default;

    /**
     * Push more data to this parser
     * @param data The data to append to the internal buffer
     */
    void push_data(Uint8View data) {
        m_data.insert(m_data.end(), data.begin(), data.end());
    }

    /**
     * Try to extract the next DNS payload from the buffer
     * @param out Output vector to store the extracted payload
     * @return true if a complete payload was extracted, false if more data is needed
     */
    bool next_payload(Uint8Vector &out) {
        switch (m_state) {
        case State::RD_SIZE:
            if (m_data.size() < 2) {
                return false; // Need more data
            }
            m_size = *(uint16_t *) m_data.data();
            m_size = ntohs(m_size);
            m_state = State::RD_PAYLOAD;
            [[fallthrough]];
        case State::RD_PAYLOAD:
            if (m_data.size() < (size_t) 2 + m_size) {
                return false; // Need more data
            }
            out = Uint8Vector(m_data.begin() + 2, m_data.begin() + 2 + m_size);
            m_data.erase(m_data.begin(), m_data.begin() + 2 + m_size);
            m_state = State::RD_SIZE;
            break;
        }
        return true;
    }
};

} // namespace ag::dns
