#pragma once

#include <memory>
#include <string>
#include <vector>

#include "common/logger.h"
#include "common/socket_address.h"
#include "dns/upstream/upstream.h"

namespace ag {
namespace dns {

class Resolver;
using ResolverPtr = std::unique_ptr<Resolver>;

class Bootstrapper {
public:
    struct Params {
        std::string_view address_string; // host to be resolved
        int default_port; // default to be used if not specified in `address_string`
        const std::vector<std::string> &bootstrap; // list of the resolving servers
        Millis timeout; // resolve timeout
        const UpstreamFactoryConfig &upstream_config; // configuration of the upstream factory which creates resolving upstream
        IfIdVariant outbound_interface; // interface to bind sockets to
    };

    explicit Bootstrapper(const Params &p);
    ~Bootstrapper();
    Bootstrapper(Bootstrapper &&);
    Bootstrapper &operator=(Bootstrapper &&);

    enum class BootstrapperError {
        AE_NO_VALID_RESOLVERS,
        AE_EMPTY_LIST,
        AE_RESOLVE_FAILED,
        AE_TEMPORARY_DISABLED,
        AE_SHUTTING_DOWN,
    };

    /**
     * Initialize bootstrapper
     * @return non-nullopt if something went wrong
     */
    Error<BootstrapperError> init();

    struct ResolveResult {
        std::vector<SocketAddress> addresses; // not empty resolved addresses list in case of success
        std::string server_name; // resolved host name
        Micros time_elapsed; // time took to resolve
        Error<BootstrapperError> error; // non-nullopt if something went wrong
    };

    std::optional<ResolveResult> try_get_ready_result();

    void request_resolve(std::function<void(ResolveResult)> &&handler);

    /**
     * Get resolved addresses from bootstrapper
     */
    auto get() {
        struct Awaitable {
            Bootstrapper *self;
            std::optional<ResolveResult> result;
            bool await_ready() {
                result = self->try_get_ready_result();
                return result.has_value();
            }
            void await_suspend(std::coroutine_handle<> h) {
                self->request_resolve([this, h](ResolveResult resolve_result) {
                    this->result = std::move(resolve_result);
                    h();
                });
            }
            ResolveResult await_resume() {
                return this->result.value();
            }
        };
        return Awaitable{.self = this};
    }

    /**
     * Remove resolved address from the cache
     * @param addr address to remove
     */
    void remove_resolved(const SocketAddress &addr);

    /**
     * Get address to resolve from bootstrapper
     */
    [[nodiscard]] std::string address() const;

    // Non-copyable
    Bootstrapper(const Bootstrapper &) = delete;
    Bootstrapper &operator=(const Bootstrapper &) = delete;

private:
    /**
     * Check if bootstrapper should be temporary disabled
     */
    Error<Bootstrapper::BootstrapperError> temporary_disabler_check();

    /**
     * Update information for temporary disabling bootstrapper
     */
    void temporary_disabler_update(bool fail);

    coro::Task<void> do_resolve();

    void complete_resolve(ResolveResult resolve_result);

    /** Logger */
    Logger m_log;
    /** Server name to resolve */
    std::string m_server_name;
    /** Server port */
    int m_server_port;
    /** Resolve timeout */
    Millis m_timeout;
    /** Resolved addresses cache */
    std::vector<SocketAddress> m_resolved_cache;
    /** List of resolvers to use */
    std::vector<ResolverPtr> m_resolvers;
    /** Resolve tasks */
    struct RequestHandler {
        std::function<void(ResolveResult)> handler;
        utils::Timer timer;
    };
    std::list<RequestHandler> m_request_handlers;
    /** Last resolve time */
    SteadyClock::time_point m_last_resolve_time;
    /** Shutdown guard */
    std::shared_ptr<bool> m_shutdown_guard;
};

using BootstrapperPtr = std::unique_ptr<Bootstrapper>;

} // namespace dns

// clang format off
template<>
struct ErrorCodeToString<dns::Bootstrapper::BootstrapperError> {
    std::string operator()(dns::Bootstrapper::BootstrapperError e) {
        switch (e) {
        case decltype(e)::AE_NO_VALID_RESOLVERS: return "Failed to create any resolver";
        case decltype(e)::AE_EMPTY_LIST: return "Empty bootstrap list";
        case decltype(e)::AE_RESOLVE_FAILED: return "Failed to resolve host";
        case decltype(e)::AE_TEMPORARY_DISABLED: return "Bootstrapping this server is temporary disabled due to many failures";
        case decltype(e)::AE_SHUTTING_DOWN: return "Shutting down";
        }
    }
};
// clang format on

} // namespace ag
