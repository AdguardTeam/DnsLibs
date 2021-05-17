#include <ag_tcp_dns_buffer.h>
#include <cassert>
#include <cstring>

#ifndef _WIN32
#include <netinet/in.h>
#else
#include <Winsock2.h>
#endif


using namespace ag;


static constexpr size_t PACKET_LENGTH_LENGTH = 2;
static constexpr size_t BUFFER_MIN_CAPACITY = 512;


static size_t ntoh_length(uint8_t *data) {
    uint16_t net_length;
    std::memcpy(&net_length, data, PACKET_LENGTH_LENGTH);
    return ntohs(net_length);
}

uint8_view tcp_dns_buffer::store(uint8_view data) {
    if (!this->total_length.has_value()) {
        if (this->buffer.empty() && data.size() >= PACKET_LENGTH_LENGTH) {
            this->total_length = ntoh_length((uint8_t *)data.data());
            data.remove_prefix(PACKET_LENGTH_LENGTH);
        } else if (this->buffer.size() < PACKET_LENGTH_LENGTH) {
            this->buffer.reserve(BUFFER_MIN_CAPACITY);
            size_t to_insert = std::min(data.size(), PACKET_LENGTH_LENGTH);
            this->buffer.insert(this->buffer.end(), data.begin(), std::next(data.begin(), (ssize_t)to_insert));
            if (this->buffer.size() >= PACKET_LENGTH_LENGTH) {
                this->total_length = ntoh_length((uint8_t *)this->buffer.data());
                this->buffer.erase(this->buffer.begin(), std::next(this->buffer.begin(), PACKET_LENGTH_LENGTH));
                data.remove_prefix(to_insert);
            }
        }

        if (this->total_length.has_value()) {
            this->buffer.reserve(std::max(this->total_length.value(), BUFFER_MIN_CAPACITY));
        } else {
            return {};
        }
    }

    size_t to_insert = std::min(data.size(), this->total_length.value() - this->buffer.size());
    this->buffer.insert(this->buffer.end(), data.begin(), std::next(data.begin(), (ssize_t)to_insert));

    assert(this->buffer.size() <= this->total_length.value());

    data.remove_prefix(to_insert);
    return data;
}

std::optional<std::vector<uint8_t>> tcp_dns_buffer::extract_packet() {
    if (!this->total_length.has_value() || this->buffer.size() < this->total_length.value()) {
        return std::nullopt;
    }

    this->total_length.reset();
    return std::exchange(this->buffer, {});
}
