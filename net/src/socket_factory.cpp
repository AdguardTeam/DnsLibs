#include <ag_socket.h>
#include "tcp_stream.h"
#include "udp_socket.h"


using namespace ag;

socket_factory::socket_factory(struct parameters parameters)
    : parameters(std::move(parameters))
    , router(route_resolver::create())
{}

socket_factory::socket_ptr socket_factory::make_socket(socket_parameters p) const {
    socket_ptr socket;

    socket::prepare_fd_callback prepare_fd = { on_prepare_fd, (void *)this };

    switch (p.proto) {
    case utils::TP_TCP:
        socket = std::make_unique<tcp_stream>(std::move(p), prepare_fd);
        break;
    case utils::TP_UDP:
        socket = std::make_unique<udp_socket>(std::move(p), prepare_fd);
        break;
    }

    return socket;
}

err_string socket_factory::prepare_fd(evutil_socket_t fd,
        const socket_address &peer, const if_id_variant &outbound_interface) const {
    if (const uint32_t *if_index = std::get_if<uint32_t>(&outbound_interface)) {
        return ag::utils::bind_socket_to_if(fd, peer.c_sockaddr()->sa_family, *if_index);
    } else if (const std::string *if_name = std::get_if<std::string>(&outbound_interface)) {
        return ag::utils::bind_socket_to_if(fd, peer.c_sockaddr()->sa_family, if_name->c_str());
    }
    if (this->router == nullptr) {
        return std::nullopt;
    }

    if (auto idx = this->router->resolve(peer); idx.has_value()) {
        auto err = ag::utils::bind_socket_to_if(fd, peer.c_sockaddr()->sa_family, *idx);
        if (err.has_value()) {
            err = std::nullopt;
            this->router->flush_cache();
            if (idx = this->router->resolve(peer); idx.has_value()) {
                err = ag::utils::bind_socket_to_if(fd, peer.c_sockaddr()->sa_family, *idx);
            }
        }
        return err;
    }

    return std::nullopt;
}

err_string socket_factory::on_prepare_fd(void *arg, evutil_socket_t fd,
        const socket_address &peer, const if_id_variant &outbound_interface) {
    auto *self = (socket_factory *)arg;
    return self->prepare_fd(fd, peer, outbound_interface);
}
