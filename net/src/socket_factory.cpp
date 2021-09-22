#include <ag_socket.h>
#include <ag_clock.h>
#include <ag_event_loop.h>
#include "tcp_stream.h"
#include "udp_socket.h"
#include "secured_socket.h"
#include "proxied_socket.h"
#include "outbound_proxy.h"
#include "outbound_http_proxy.h"
#include "outbound_socks_proxy.h"
#include "outbound_direct_proxy.h"


using namespace ag;


static constexpr std::chrono::seconds PROXY_UNAVAILABLE_TIMEOUT(10);
static constexpr std::chrono::seconds PROXY_AVAILABLE_TIMEOUT(3);


enum proxy_availability_status {
    /// There were no connections to the proxy server recently
    PAS_UNKNOWN,
    /// There was a successful connection to the proxy server recently
    PAS_AVAILABLE,
    /// All the recent connections to the proxy server had failed
    PAS_UNAVAILABLE,
};

struct socket_factory::outbound_proxy_state {
    /// The main proxy
    std::unique_ptr<outbound_proxy> main_proxy;
    /// The fallback proxy: used in case of the main one is not available
    std::unique_ptr<outbound_proxy> fallback_proxy;

    std::mutex guard;
    /// Whether the proxy is available. If not, the behavior depends on
    /// `outbound_proxy_settings#ignore_if_unavailable` flag
    expiring_value<proxy_availability_status, PAS_UNKNOWN> availability_status;
    /// Used for example to reset re-routed directly connection
    event_loop_ptr event_loop;
    /// Whether the event for resetting bypassed connections is scheduled
    bool reset_task_scheduled = false;
    /// The next reset event subscriber ID
    uint32_t next_subscriber_id = 0;
    /// The reset event subscribers
    hash_map<uint32_t, reset_bypassed_proxy_connections_subscriber> reset_subscribers;

    static void on_successful_proxy_connection(void *arg) {
        auto *self = (socket_factory *)arg;
        ((direct_oproxy *)self->proxy->fallback_proxy.get())->reset_connections();
        self->proxy->reset_task_scheduled = false;
        self->proxy->event_loop.reset();
    }

    static proxied_socket::proxy_connection_failed_result on_proxy_connection_failed(
            void *arg, std::optional<int> err) {
        auto *self = (socket_factory *)arg;
        switch (self->on_proxy_connection_failed(err)) {
        case SFPCFR_CLOSE_CONNECTION:
            break;
        case SFPCFR_RETRY_DIRECTLY:
            return proxied_socket::fallback{ self->proxy->fallback_proxy.get() };
        }
        return proxied_socket::close_connection{};
    }
};


socket_factory::socket_factory(struct parameters parameters)
    : parameters(std::move(parameters))
    , router(route_resolver::create())
{
    if (this->parameters.oproxy_settings != nullptr) {
        this->proxy = std::make_unique<outbound_proxy_state>();
        this->proxy->main_proxy.reset(this->make_proxy());
        this->proxy->fallback_proxy.reset(this->make_fallback_proxy());
    }
}

socket_factory::~socket_factory() = default;

socket_factory::socket_ptr socket_factory::make_socket(socket_parameters p) const {
    socket_ptr socket;
    if (p.ignore_proxy_settings || !this->should_route_through_proxy(p.proto)) {
        socket = this->make_direct_socket(std::move(p));
    } else {
        socket = std::make_unique<proxied_socket>(proxied_socket::parameters{
                *this->proxy->main_proxy,
                std::move(p),
                { on_prepare_fd, (void *)this },
                {
                    outbound_proxy_state::on_successful_proxy_connection,
                    outbound_proxy_state::on_proxy_connection_failed,
                    (void *)this,
                },
        });
    }

    return socket;
}

socket_factory::socket_ptr socket_factory::make_secured_socket(socket_parameters p,
        secure_socket_parameters secure_parameters) const {
    return this->make_secured_socket(this->make_socket(std::move(p)), std::move(secure_parameters));
}

socket_factory::socket_ptr socket_factory::make_direct_socket(socket_parameters p) const {
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

socket_factory::socket_ptr socket_factory::make_secured_socket(socket_ptr underlying_socket,
        secure_socket_parameters secure_parameters) const {
    return std::make_unique<secured_socket>(
            std::move(underlying_socket)
            , this->parameters.verifier
            , std::move(secure_parameters)
    );
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

const outbound_proxy_settings *socket_factory::get_outbound_proxy_settings() const {
    return this->parameters.oproxy_settings;
}

bool socket_factory::should_route_through_proxy(utils::transport_protocol proto) const {
    if (this->proxy == nullptr) {
        return false;
    }
    if (!this->proxy->main_proxy->get_supported_protocols().test(proto)) {
        return false;
    }

    std::scoped_lock l(this->proxy->guard);
    return this->proxy->availability_status.get() != PAS_UNAVAILABLE
            || !this->get_outbound_proxy_settings()->ignore_if_unavailable;
}

bool socket_factory::is_proxy_available() const {
    const outbound_proxy_settings *settings = this->get_outbound_proxy_settings();
    if (settings == nullptr || this->proxy == nullptr) {
        return false;
    }

    if (!settings->ignore_if_unavailable) {
        return true;
    }

    std::scoped_lock l(this->proxy->guard);
    return this->proxy->availability_status.get() != PAS_UNAVAILABLE;
}

void socket_factory::on_successful_proxy_connection() {
    std::scoped_lock l(this->proxy->guard);
    this->proxy->availability_status = { PAS_AVAILABLE, PROXY_AVAILABLE_TIMEOUT };
}

socket_factory::proxy_connection_failed_result socket_factory::on_proxy_connection_failed(std::optional<int> err) {
    if (err != utils::AG_ECONNREFUSED) {
        return SFPCFR_CLOSE_CONNECTION;
    }

    if (!this->get_outbound_proxy_settings()->ignore_if_unavailable) {
        return SFPCFR_CLOSE_CONNECTION;
    }

    if (std::scoped_lock l(this->proxy->guard);
            this->proxy->availability_status.get() != PAS_AVAILABLE) {
        this->proxy->availability_status = { PAS_UNAVAILABLE, PROXY_UNAVAILABLE_TIMEOUT };
    }

    if (!this->proxy->reset_task_scheduled) {
        if (this->proxy->event_loop == nullptr) {
            this->proxy->event_loop = event_loop::create();
        }

        this->subscribe_to_reset_bypassed_proxy_connections_event({ on_reset_bypassed_proxy_connections, this });

        this->proxy->event_loop->schedule(PROXY_UNAVAILABLE_TIMEOUT,
                [this] () {
                    decltype(this->proxy->reset_subscribers) subscribers;

                    {
                        std::scoped_lock l(this->proxy->guard);
                        this->proxy->reset_task_scheduled = false;
                        subscribers.swap(this->proxy->reset_subscribers);
                    }

                    for (auto &[_, s] : subscribers) {
                        s.func(s.arg);
                    }
                });
    }

    return SFPCFR_RETRY_DIRECTLY;
}

uint32_t socket_factory::subscribe_to_reset_bypassed_proxy_connections_event(
        reset_bypassed_proxy_connections_subscriber subscriber) {
    std::scoped_lock l(this->proxy->guard);
    return this->proxy->reset_subscribers.emplace(this->proxy->next_subscriber_id++, subscriber).first->first;
}

void socket_factory::unsubscribe_from_reset_bypassed_proxy_connections_event(uint32_t id) {
    std::scoped_lock l(this->proxy->guard);
    this->proxy->reset_subscribers.erase(id);
}

err_string socket_factory::on_prepare_fd(void *arg, evutil_socket_t fd,
        const socket_address &peer, const if_id_variant &outbound_interface) {
    auto *self = (socket_factory *)arg;
    return self->prepare_fd(fd, peer, outbound_interface);
}

outbound_proxy *socket_factory::make_proxy() const {
    struct outbound_proxy::parameters oproxy_params = { this->parameters.verifier, { on_make_proxy_socket, (void *)this } };

    outbound_proxy *oproxy = nullptr;
    switch (this->parameters.oproxy_settings->protocol) {
    case outbound_proxy_protocol::HTTP_CONNECT:
    case outbound_proxy_protocol::HTTPS_CONNECT:
        oproxy = new http_oproxy(this->parameters.oproxy_settings, oproxy_params);
        break;
    case outbound_proxy_protocol::SOCKS4:
    case outbound_proxy_protocol::SOCKS5:
    case outbound_proxy_protocol::SOCKS5_UDP:
        oproxy = new socks_oproxy(this->parameters.oproxy_settings, oproxy_params);
        break;
    }

    return oproxy;
}

outbound_proxy *socket_factory::make_fallback_proxy() const {
    return new direct_oproxy({ this->parameters.verifier, { on_make_proxy_socket, (void *)this } });
}

socket_factory::socket_ptr socket_factory::on_make_proxy_socket(void *arg,
        utils::transport_protocol proto, std::optional<secure_socket_parameters> secure_parameters) {
    auto *self = (socket_factory *)arg;
    socket_ptr s = self->make_direct_socket({ proto });
    if (secure_parameters.has_value()) {
        s = self->make_secured_socket(std::move(s), std::move(secure_parameters.value()));
    }
    return s;
}

void socket_factory::on_reset_bypassed_proxy_connections(void *arg) {
    auto *self = (socket_factory *)arg;
    self->proxy->reset_task_scheduled = false;
    ((direct_oproxy *)self->proxy->fallback_proxy.get())->reset_connections();
}
