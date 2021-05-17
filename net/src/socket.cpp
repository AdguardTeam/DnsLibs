#include <ag_socket.h>
#include <atomic>


using namespace ag;


static std::atomic_size_t next_id = { 0 };


socket::socket(const std::string &logger_name, socket_factory::socket_parameters parameters, prepare_fd_callback prepare_fd)
    : log(create_logger(logger_name))
    , id(next_id.fetch_add(1, std::memory_order::memory_order_relaxed))
    , parameters(std::move(parameters))
    , prepare_fd(prepare_fd)
{}

utils::transport_protocol socket::get_protocol() const {
    return this->parameters.proto;
}

socket_address socket::get_peer() const {
    std::optional<evutil_socket_t> fd = this->get_fd();
    if (!fd.has_value()) {
        return {};
    }

    return utils::get_peer_address(fd.value()).value_or(socket_address{});
}
