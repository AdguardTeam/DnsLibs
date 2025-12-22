#include <errno.h>
#include <future>
#include <unistd.h>
#include <sys/ioctl.h>

#include "dns/common/event_loop.h"
#include "system_resolver.h"

#include "android_res_api.h"
using ag::dns::AndroidResApi;

namespace ag::dns {

static ag::Logger g_log{"SystemResolver"};

static constexpr int INVALID_FD = -1;
static constexpr int MIN_VALID_FD = 0;
static constexpr size_t DNS_PACKET_BUFFER_SIZE = 4096;

class SystemResolver::Impl {
public:
    Impl(EventLoop *loop, Millis timeout, net_handle_t network_handle)
            : m_loop(loop)
            , m_network_handle(network_handle)
            , m_timeout(timeout) {
    }

    ~Impl() {
        for (auto it = m_requests.begin(); it != m_requests.end();) {
            auto next_it = std::next(it);
            it->second.error = make_error(SystemResolverError::AE_SHUTTING_DOWN);
            complete_request(it->second); // it removed here
            it = next_it;
        }
    }

    struct Request {
        uint64_t id;
        Impl *parent;
        std::string domain;
        ldns_rr_type rr_type;
        SystemResolver::LdnsRrListPtr rr_list{ldns_rr_list_new()};
        Error<SystemResolverError> error;
        int query_fd = INVALID_FD;
        bool fd_consumed = false;
        UvPtr<uv_poll_t> poll_event;
        UvPtr<uv_timer_t> timer_event;
        std::coroutine_handle<> continuation;
        std::shared_ptr<bool> guard = std::make_shared<bool>();
    };

    struct ResResult {
        std::array<uint8_t, DNS_PACKET_BUFFER_SIZE> answer_buffer;
        int len = 0;
        int rcode = 0;
    };

    auto resolve(std::string_view domain, ldns_rr_type rr_type) {
        uint64_t id = m_next_request_id++;
        auto &req = m_requests[id];
        req.id = id;
        req.parent = this;
        req.domain = std::string(domain);
        req.rr_type = rr_type;

        struct Awaitable {
            Request *req;

            auto await_ready() {
                if (!AndroidResApi::is_available()) {
                    req->error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
                    return true;
                }

                // 1. Create DNS query packet
                ldns_pkt *query_pkt = ldns_pkt_query_new(
                        ldns_dname_new_frm_str(req->domain.c_str()), req->rr_type, LDNS_RR_CLASS_IN, LDNS_RD);
                ldns_pkt_set_random_id(query_pkt);

                if (!query_pkt) {
                    req->error = make_error(SystemResolverError::AE_DECODE_ERROR);
                    return true;
                }

                uint8_t *wire_data = nullptr;
                size_t wire_size = 0;
                ldns_status status = ldns_pkt2wire(&wire_data, query_pkt, &wire_size);
                ldns_pkt_free(query_pkt);

                if (status != LDNS_STATUS_OK) {
                    req->error = make_error(SystemResolverError::AE_DECODE_ERROR);
                    return true;
                }

                // 2. Call android_res_nsend, get fd
                tracelog(g_log, "Calling AndroidResApi::nsend with network handle: {}, wire_size: {}",
                        req->parent->m_network_handle, wire_size);
                req->query_fd = AndroidResApi::nsend(req->parent->m_network_handle, wire_data, wire_size, /*flags*/ 0);
                free(wire_data);

                tracelog(g_log, "AndroidResApi::nsend returned fd: {} for network handle: {}", req->query_fd,
                        req->parent->m_network_handle);

                if (req->query_fd < MIN_VALID_FD) {
                    tracelog(g_log, "Invalid fd returned from nsend: {}, this indicates android_res_nsend failed",
                            req->query_fd);
                    req->error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
                    tracelog(g_log, "Completing request immediately with error due to invalid fd");
                    return true;
                }

                // 3. Setup fd polling for read events
                req->poll_event = Uv<uv_poll_t>::create_with_parent(req);
                if (0 != uv_poll_init(req->parent->m_loop->handle(), req->poll_event->raw(), req->query_fd)) {
                    req->error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
                    return true;
                }
                // Poll for read events on the fd
                if (0 != uv_poll_start(
                    req->poll_event->raw(), UV_READABLE, on_uv_read)) {
                    req->error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
                    return true;
                }

                // 4. Setup timeout timer
                req->timer_event = Uv<uv_timer_t>::create_with_parent(req);
                if (0 != uv_timer_init(req->parent->m_loop->handle(), req->timer_event->raw())) {
                    req->error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
                    return true;
                }
                if (0 != uv_timer_start(
                        req->timer_event->raw(), on_uv_timer, req->parent->m_timeout.count(), /*repeat*/ 0)) {
                    req->error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
                    return true;
                }

                tracelog(g_log, "Requested domain {} rrtype {}", req->domain, (int) req->rr_type);
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
                    result.len = AndroidResApi::nresult(fd, &result.rcode,
                                                        result.answer_buffer.data(),
                                                        result.answer_buffer.size());
                    tracelog(g_log, "on_uv_read: nresult returned result_len={}, rcode={}", result.len, result.rcode);
                    req->parent->process_result(*req, result);
                }
            }

            static void on_uv_timer(uv_timer_t *handle) {
                auto req = (Request *) Uv<uv_timer_t>::parent_from_data(handle->data);
                if (!req) {
                    return;
                }
                req->error = make_error(SystemResolverError::AE_TIMED_OUT);
                req->parent->complete_request(*req);
            }

            auto await_suspend(std::coroutine_handle<> continuation) {
                req->continuation = continuation;
            }

            Result<SystemResolver::LdnsRrListPtr, SystemResolverError> await_resume() {
                auto node = req->parent->m_requests.extract(req->id);
                if (node.mapped().error) {
                    return node.mapped().error;
                } else {
                    return std::move(node.mapped().rr_list);
                }
            }
        };
        return Awaitable{.req = &req};
    }

    void process_result(Request &req, ResResult &result) {
        tracelog(g_log, "process_result: Processing result for fd {}", req.query_fd);

        if (result.len < 0) {
            if (result.len == -ENOENT) {
                req.error = make_error(SystemResolverError::AE_DOMAIN_NOT_FOUND);
            } else if (result.len == -ETIMEDOUT) {
                req.error = make_error(SystemResolverError::AE_TIMED_OUT);
            } else {
                tracelog(g_log, "process_result: Android API error: {}", strerror(-result.len));
                req.error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
            }
            complete_request(req);
            return;
        }

        // Success - we have data
        req.query_fd = INVALID_FD;

        // Handle DNS response codes
        if (result.rcode == LDNS_RCODE_NXDOMAIN) {
            req.error = make_error(SystemResolverError::AE_DOMAIN_NOT_FOUND);
            complete_request(req);
            return;
        } else if (result.rcode != LDNS_RCODE_NOERROR) {
            req.error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
            complete_request(req);
            return;
        }

        // Parse DNS response
        ldns_pkt *response_pkt = nullptr;
        ldns_status status = ldns_wire2pkt(&response_pkt, result.answer_buffer.data(), result.len);
        if (status != LDNS_STATUS_OK) {
            req.error = make_error(SystemResolverError::AE_DECODE_ERROR);
            complete_request(req);
            return;
        }

        // Extract answer records
        ldns_rr_list *answer_list = ldns_pkt_answer(response_pkt);
        if (answer_list) {
            for (size_t i = 0; i < ldns_rr_list_rr_count(answer_list); ++i) {
                ldns_rr *rr = ldns_rr_list_rr(answer_list, i);
                if (ldns_rr_get_type(rr) == req.rr_type) {
                    ldns_rr_list_push_rr(req.rr_list.get(), ldns_rr_clone(rr));
                }
            }
        }

        ldns_pkt_free(response_pkt);

        tracelog(g_log, "Resolved {} with {} records", req.domain, ldns_rr_list_rr_count(req.rr_list.get()));
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

SystemResolver::SystemResolver(ag::dns::SystemResolver::ConstructorAccess, ag::dns::EventLoop *loop, Millis timeout,
        net_handle_t network_handle) {
    m_pimpl = std::make_unique<Impl>(loop, timeout, network_handle);
}

SystemResolver::~SystemResolver() = default;

ag::Result<std::unique_ptr<SystemResolver>, SystemResolverError> SystemResolver::create(
        EventLoop *loop, Millis timeout, net_handle_t network_handle) {
    if (!AndroidResApi::is_available()) {
        return make_error(SystemResolverError::AE_INIT_ERROR);
    }
    std::unique_ptr<SystemResolver> ret =
            std::make_unique<SystemResolver>(ConstructorAccess{}, loop, timeout, network_handle);
    if (!ret || !ret->m_pimpl) {
        return make_error(SystemResolverError::AE_INIT_ERROR);
    }
    return ret;
}

coro::Task<Result<SystemResolver::LdnsRrListPtr, SystemResolverError>> SystemResolver::resolve(
        std::string_view domain, ldns_rr_type rr_type) {
    co_return co_await m_pimpl->resolve(domain, rr_type);
}

} // namespace ag::dns
