#pragma once


#include <vector>
#include <optional>
#include "common/defs.h"


namespace ag::dns {

class TcpDnsBuffer {
public:
    TcpDnsBuffer() = default;
    ~TcpDnsBuffer() = default;

    /**
     * Store a chunk of data
     * @param data the data chunk
     * @return a part of the chunk remaining after the DNS packet
     */
    Uint8View store(Uint8View data);

    /**
     * Try to extract a packet from the buffer
     * @return some packet if it's complete
     */
    std::optional<Uint8Vector> extract_packet();

private:
    std::optional<size_t> m_total_length;
    Uint8Vector m_buffer;
};

}
