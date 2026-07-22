#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <map>

#include <android/multinetwork.h>

#include "common/logger.h"
#include "dns/common/event_loop.h"

#include "android_res_api.h"
#include "upstream_system.h"

#ifdef USE_INTERFACE_NAMES_IN_SYSTEM_UPSTREAM
#include "android_context_manager.h"
#endif

namespace ag::dns {

static ag::Logger g_log{"SystemUpstream"};

static constexpr int INVALID_FD = -1;
static constexpr int MIN_VALID_FD = 0;
static constexpr size_t DNS_PACKET_BUFFER_SIZE = 4096;

/**
 * Sends DNS queries via `android_res_nsend()` and returns the raw replies.
 *
 * Unlike the Apple system resolver (a DNSService wrapper, which only reports individual
 * records), the Android API hands us the reply exactly as it came from netd, so it is
 * simply parsed and passed through: no record extraction and no reply re-assembly.
 */
class SystemUpstream::Impl {
public:
    /**
     * A successful query yields the raw reply packet, or a null packet if the system
     * resolver reported "no such name" without giving us a reply to return.
     */
    using SendResult = Result<ldns_pkt_ptr, DnsError>;

    Impl(EventLoop *loop, Millis timeout, net_handle_t network_handle)
            : m_loop(loop)
            , m_network_handle(network_handle)
            , m_timeout(timeout) {
    }

    ~Impl() {
        for (auto it = m_requests.begin(); it != m_requests.end();) {
            auto next_it = std::next(it);
            it->second.error = make_error(DnsError::AE_SHUTTING_DOWN);
            complete_request(it->second); // it removed here
            it = next_it;
        }
    }

    struct Request {
        uint64_t id;
        Impl *parent;
        Uint8View query;
        ldns_pkt_ptr reply;
        Error<DnsError> error;
        int query_fd = INVALID_FD;
        bool fd_consumed = false;
        UvPtr<uv_poll_t> poll_event;
        UvPtr<uv_timer_t> timer_event;
        std::coroutine_handle<> continuation;
    };

    struct ResResult {
        std::array<uint8_t, DNS_PACKET_BUFFER_SIZE> answer_buffer;
        int len = 0;
        int rcode = 0;
    };

    /**
     * Sends a DNS query in wire format and awaits the reply.
     * @param query The wire-format query. Must outlive the awaitable.
     */
    auto send(Uint8View query) {
        uint64_t id = m_next_request_id++;
        auto &req = m_requests[id];
        req.id = id;
        req.parent = this;
        req.query = query;

        struct Awaitable {
            Request *req;

            auto await_ready() {
                // 1. Call android_res_nsend, get fd
                tracelog(g_log, "Calling AndroidResApi::nsend with network handle: {}, wire_size: {}",
                        req->parent->m_network_handle, req->query.size());
                req->query_fd = AndroidResApi::nsend(
                        req->parent->m_network_handle, req->query.data(), req->query.size(), /*flags*/ 0);

                tracelog(g_log, "AndroidResApi::nsend returned fd: {} for network handle: {}", req->query_fd,
                        req->parent->m_network_handle);

                if (req->query_fd < MIN_VALID_FD) {
                    tracelog(g_log, "Invalid fd returned from nsend: {}, this indicates android_res_nsend failed",
                            req->query_fd);
                    req->error = make_error(DnsError::AE_INTERNAL_ERROR, "android_res_nsend() failed");
                    tracelog(g_log, "Completing request immediately with error due to invalid fd");
                    return true;
                }

                // 2. Setup fd polling for read events
                req->poll_event = Uv<uv_poll_t>::create_with_parent(req);
                if (0 != uv_poll_init(req->parent->m_loop->handle(), req->poll_event->raw(), req->query_fd)) {
                    req->error = make_error(DnsError::AE_INTERNAL_ERROR, "Failed to init poll event");
                    return true;
                }
                // Poll for read events on the fd
                if (0 != uv_poll_start(req->poll_event->raw(), UV_READABLE, on_uv_read)) {
                    req->error = make_error(DnsError::AE_INTERNAL_ERROR, "Failed to start poll event");
                    return true;
                }

                // 3. Setup timeout timer
                req->timer_event = Uv<uv_timer_t>::create_with_parent(req);
                if (0 != uv_timer_init(req->parent->m_loop->handle(), req->timer_event->raw())) {
                    req->error = make_error(DnsError::AE_INTERNAL_ERROR, "Failed to init timer event");
                    return true;
                }
                if (0
                        != uv_timer_start(
                                req->timer_event->raw(), on_uv_timer, req->parent->m_timeout.count(), /*repeat*/ 0)) {
                    req->error = make_error(DnsError::AE_INTERNAL_ERROR, "Failed to start timer event");
                    return true;
                }

                return false;
            }

            static void on_uv_read(uv_poll_t *handle, int status, int events) {
                auto *req = static_cast<Request *>(Uv<uv_poll_t>::parent_from_data(handle->data));
                if (!req) {
                    return;
                }
                if (events & UV_READABLE) {
                    // netd always writes data in two chunks - header + body.
                    // android_res_nresult requires blocking read, or will return -EIO if there is no body.
                    // So, set blocking mode and execute in threadpool for blocking tasks
                    req->poll_event.reset();
                    if (req->fd_consumed) {
                        dbglog(g_log, "on_uv_read: fd {} already consumed, ignoring read event", req->query_fd);
                        return;
                    }
                    req->fd_consumed = true;
                    int fd = req->query_fd;
                    ResResult result;
                    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
                    result.len = AndroidResApi::nresult(
                            fd, &result.rcode, result.answer_buffer.data(), result.answer_buffer.size());
                    tracelog(g_log, "on_uv_read: nresult returned result_len={}, rcode={}", result.len, result.rcode);
                    req->parent->process_result(*req, result);
                }
            }

            static void on_uv_timer(uv_timer_t *handle) {
                auto req = (Request *) Uv<uv_timer_t>::parent_from_data(handle->data);
                if (!req) {
                    return;
                }
                req->error = make_error(DnsError::AE_TIMED_OUT);
                req->parent->complete_request(*req);
            }

            auto await_suspend(std::coroutine_handle<> continuation) {
                req->continuation = continuation;
            }

            SendResult await_resume() {
                auto node = req->parent->m_requests.extract(req->id);
                if (node.mapped().error) {
                    return node.mapped().error;
                }
                return std::move(node.mapped().reply);
            }
        };
        return Awaitable{.req = &req};
    }

    void process_result(Request &req, ResResult &result) {
        tracelog(g_log, "process_result: Processing result for fd {}", req.query_fd);

        if (result.len < 0) {
            if (result.len == -ENOENT) {
                // No reply to pass through: the caller synthesizes a negative response.
                tracelog(g_log, "process_result: no such name");
            } else if (result.len == -ETIMEDOUT) {
                req.error = make_error(DnsError::AE_TIMED_OUT);
            } else {
                tracelog(g_log, "process_result: Android API error: {}", strerror(-result.len));
                req.error = make_error(DnsError::AE_INTERNAL_ERROR, strerror(-result.len));
            }
            complete_request(req);
            return;
        }

        // Success - we have data
        req.query_fd = INVALID_FD;

        if (result.len > (int) result.answer_buffer.size()) {
            // Shouldn't happen: netd is expected to fail the query instead of overflowing
            // the buffer, but don't parse past the buffer if it ever reports it did.
            req.error = make_error(DnsError::AE_INTERNAL_ERROR, "Reply doesn't fit in the answer buffer");
            complete_request(req);
            return;
        }

        // netd returns the reply as it came from the server, so return it as is:
        // no need to decompose it into records and rebuild the reply around them.
        ldns_pkt *reply_pkt = nullptr;
        ldns_status status = ldns_wire2pkt(&reply_pkt, result.answer_buffer.data(), result.len);
        if (status != LDNS_STATUS_OK) {
            req.error = make_error(DnsError::AE_DECODE_ERROR, ldns_get_errorstr_by_id(status));
            complete_request(req);
            return;
        }
        req.reply.reset(reply_pkt);

        tracelog(g_log, "Got a reply with rcode {} and {} records in the answer section",
                (int) ldns_pkt_get_rcode(reply_pkt), ldns_pkt_ancount(reply_pkt));
        complete_request(req);
    }

    void complete_request(Request &req) {
        if (req.poll_event) {
            uv_poll_stop(req.poll_event->raw());
        }
        if (req.timer_event) {
            uv_timer_stop(req.timer_event->raw());
        }

        if (req.query_fd >= MIN_VALID_FD && !req.fd_consumed) {
            AndroidResApi::cancel(req.query_fd);
            req.query_fd = INVALID_FD;
        }

        if (req.continuation) {
            std::exchange(req.continuation, nullptr).resume();
        } else {
            m_requests.erase(req.id);
        }
    }

    EventLoop *m_loop = nullptr;
    net_handle_t m_network_handle = NETWORK_UNSPECIFIED;
    uint64_t m_next_request_id = 0;
    std::map<uint64_t, Request> m_requests;
    Millis m_timeout;
};

SystemUpstream::SystemUpstream(const UpstreamOptions &opts, const UpstreamFactoryConfig &config)
        : Upstream(opts, config)
        , m_log(AG_FMT("System upstream ({})", opts.address))
        , m_interface(interface_from_address(opts.address)) {
}

SystemUpstream::~SystemUpstream() = default;

Error<Upstream::InitError> SystemUpstream::init() {
    net_handle_t network_handle = NETWORK_UNSPECIFIED;

    if (!m_interface.empty()) {
#ifdef USE_INTERFACE_NAMES_IN_SYSTEM_UPSTREAM
        auto handle_opt = AndroidContextManager::get_network_handle_for_interface(m_interface);
        if (!handle_opt.has_value()) {
            return make_error(InitError::AE_INVALID_ADDRESS, AG_FMT("Invalid interface name: {}", m_interface));
        }
        tracelog(g_log, "Resolved interface '{}' to network handle: {}", m_interface, handle_opt.value());
        network_handle = handle_opt.value();
#else
        return make_error(InitError::AE_INVALID_ADDRESS,
                AG_FMT("Interface names not supported in this build (interface: {})", m_interface));
#endif
    }

    if (!AndroidResApi::is_available()) {
        return make_error(InitError::AE_SYSTEMRESOLVER_INIT_FAILED, "android_res_* functions are not available");
    }

    m_pimpl = std::make_unique<Impl>(&config().loop, config().timeout, network_handle);
    return {};
}

coro::Task<Upstream::ExchangeResult> SystemUpstream::exchange(const ldns_pkt *request_pkt, const DnsMessageInfo *info) {
    uint8_t *wire_data = nullptr;
    size_t wire_size = 0;
    ldns_status status = ldns_pkt2wire(&wire_data, request_pkt, &wire_size);
    AllocatedPtr<uint8_t> wire{wire_data};
    if (status != LDNS_STATUS_OK) {
        co_return make_error(DnsError::AE_ENCODE_ERROR, ldns_get_errorstr_by_id(status));
    }

    // Nothing below this line may touch `this`: the awaiting request is resumed with
    // AE_SHUTTING_DOWN from the destructor, i.e. after the upstream itself is gone.
    auto result = co_await m_pimpl->send({wire.get(), wire_size});
    if (result.has_error()) {
        co_return result.error();
    }

    if (ldns_pkt_ptr &reply_pkt = result.value()) {
        // netd is free to rewrite the query ID, but the caller matches the reply against
        // the request it made, so restore it.
        ldns_pkt_set_id(reply_pkt.get(), ldns_pkt_id(request_pkt));
        co_return std::move(reply_pkt);
    }

    // The system resolver said "no such name" without giving us a reply to return.
    ldns_pkt_ptr nxdomain_pkt{ldns_pkt_clone(request_pkt)};
    ldns_pkt_set_qr(nxdomain_pkt.get(), true);
    ldns_pkt_set_aa(nxdomain_pkt.get(), false);
    ldns_pkt_set_rd(nxdomain_pkt.get(), true);
    ldns_pkt_set_ra(nxdomain_pkt.get(), true);
    ldns_pkt_set_ad(nxdomain_pkt.get(), false);
    ldns_pkt_set_cd(nxdomain_pkt.get(), false);
    ldns_pkt_set_rcode(nxdomain_pkt.get(), LDNS_RCODE_NXDOMAIN);
    ldns_pkt_push_rr(nxdomain_pkt.get(), LDNS_SECTION_AUTHORITY, create_soa(request_pkt));
    co_return std::move(nxdomain_pkt);
}

} // namespace ag::dns
