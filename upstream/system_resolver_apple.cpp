#include <future>
#include <optional>

#include <fmt/format.h>

#include "dns/common/event_loop.h"
#include "system_resolver.h"
#include <dns_sd.h>

namespace ag::dns {

static ag::Logger g_log{"SystemResolver"};

class SystemResolver::Impl {
public:
    Impl(EventLoop *loop, Millis timeout, uint32_t if_index)
            : m_loop(loop)
            , m_if_index(if_index)
            , m_timeout(timeout) {
    }

    ~Impl() {
        // The pending requests are completed by resuming their coroutines below, which may try to
        // resolve more names (e.g. if the caller retries on `AE_SHUTTING_DOWN`). Refuse them, so
        // that they can't modify `m_requests` while it's being drained.
        m_destroying = true;
        while (!m_requests.empty()) {
            Request &req = m_requests.begin()->second;
            req.error = make_error(SystemResolverError::AE_SHUTTING_DOWN);
            complete_request(req);
        }
    }

    using ServiceRefPtr = ag::UniquePtr<std::remove_pointer_t<DNSServiceRef>, &DNSServiceRefDeallocate>;

    struct Request {
        uint64_t id;
        Impl *parent;
        std::string domain;
        ldns_rr_type rr_type;
        bool rr_type_received;
        SystemResolver::LdnsRrListPtr rr_list{ldns_rr_list_new()};
        Error<SystemResolverError> error;
        ServiceRefPtr service;
        UvPtr<uv_poll_t> poll_event;
        UvPtr<uv_timer_t> timer_event;
        std::coroutine_handle<> continuation;
    };

    auto resolve(std::string_view domain, ldns_rr_type rr_type) {
        struct Awaitable {
            Request *req = nullptr; ///< The request, or null if it was rejected.
            std::optional<Result<SystemResolver::LdnsRrListPtr, SystemResolverError>> result;

            auto await_ready() {
                if (req == nullptr) {
                    return true;
                }
                DNSServiceRef service_ref;

                auto error_code = DNSServiceQueryRecord(&service_ref,
                        kDNSServiceFlagsUnicastResponse | kDNSServiceFlagsReturnIntermediates
                                | kDNSServiceFlagAnsweredFromCache | kDNSServiceFlagsTimeout,
                        req->parent->m_if_index, req->domain.data(), req->rr_type, kDNSServiceClass_IN,
                        handle_dns_service_query_record_reply, req);

                if (error_code != kDNSServiceErr_NoError) {
                    req->error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
                    return true;
                }
                req->service.reset(service_ref);

                req->poll_event = Uv<uv_poll_t>::create_with_parent(req);
                uv_os_sock_t fd = DNSServiceRefSockFD(service_ref);
                if (0 != uv_poll_init_socket(req->parent->m_loop->handle(), req->poll_event->raw(), fd)) {
                    req->error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
                    return true;
                }
                if (0 != uv_poll_start(req->poll_event->raw(), UV_READABLE, on_uv_read)) {
                    req->error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
                    return true;
                }
                req->timer_event = Uv<uv_timer_t>::create_with_parent(req);
                if (0 != uv_timer_init(req->parent->m_loop->handle(), req->timer_event->raw())) {
                    req->error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
                    return true;
                }
                if (0 != uv_timer_start(req->timer_event->raw(), on_uv_timer, req->parent->m_timeout.count(), 0)) {
                    req->error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
                    return true;
                }

                tracelog(g_log, "Requested domain {} rrtype {}", req->domain,
                        AllocatedPtr<char>{ldns_rr_type2str(ldns_rr_type(req->rr_type))}.get()
                                ?: AG_FMT("TYPE{}", (int) req->rr_type));
                return false;
            }

            static void on_uv_read(uv_poll_t *handle, int status, int events) {
                if (events & UV_READABLE) {
                    if (auto req = (Request *) Uv<uv_poll_t>::parent_from_data(handle->data)) {
                        if (req->service) {
                            DNSServiceProcessResult(req->service.get());
                        } else {
                            req->poll_event.reset();
                        }
                    }
                }
            }

            static void on_uv_timer(uv_timer_t *handle) {
                if (auto req = (Request *) Uv<uv_poll_t>::parent_from_data(handle->data)) {
                    req->error = make_error(SystemResolverError::AE_TIMED_OUT);
                    req->parent->complete_request(*req);
                    return;
                }
            }

            auto await_suspend(std::coroutine_handle<> continuation) {
                req->continuation = continuation;
            }

            Result<SystemResolver::LdnsRrListPtr, SystemResolverError> await_resume() {
                if (req == nullptr) {
                    return std::move(result.value());
                }
                auto node = req->parent->m_requests.extract(req->id);
                if (node.mapped().error) {
                    return node.mapped().error;
                } else {
                    return std::move(node.mapped().rr_list);
                }
            }

            static SystemResolverError dns_error_to_resolver_error(int errorCode) {
                switch (errorCode) {
                case kDNSServiceErr_NoSuchRecord:
                    return SystemResolverError::AE_RECORD_NOT_FOUND;
                case kDNSServiceErr_NoSuchName:
                    return SystemResolverError::AE_DOMAIN_NOT_FOUND;
                case kDNSServiceErr_Timeout:
                    return SystemResolverError::AE_TIMED_OUT;
                default:
                    return SystemResolverError::AE_SYSTEM_RESOLVE_ERROR;
                }
            }

            /**
             * Handles the reply from a DNSServiceQueryRecord request.
             * @param sdRef The DNSServiceRef initialized by DNSServiceQueryRecord.
             * @param flags Possible values are kDNSServiceFlagsMoreComing and kDNSServiceFlagsAdd.
             * @param interfaceIndex The interface on which the query was resolved.
             * @param errorCode Indicates whether the operation succeeded.
             * @param fullname The full domain name of the resource record.
             * @param rrtype The type of the resource record.
             * @param rrclass The class of the resource record.
             * @param rdlen The length of the rdata.
             * @param rdata The raw rdata of the resource record.
             * @param ttl The time to live of the resource record.
             * @param context A pointer to the user-defined context.
             */
            static void handle_dns_service_query_record_reply(DNSServiceRef sdRef [[maybe_unused]],
                    DNSServiceFlags flags, uint32_t interfaceIndex [[maybe_unused]], DNSServiceErrorType errorCode,
                    const char *fullname, uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, const void *rdata,
                    uint32_t ttl, void *context) {
                tracelog(g_log, "Reply: error {}, {} {} {} {} {}, flags {:x}", errorCode, fullname ?: "(null)", ttl,
                        AllocatedPtr<char>{ldns_rr_class2str(ldns_rr_class(rrclass))}.get()
                                ?: AG_FMT("CLASS{}", rrclass),
                        AllocatedPtr<char>{ldns_rr_type2str(ldns_rr_type(rrtype))}.get() ?: AG_FMT("TYPE{}", rrtype),
                        utils::encode_to_hex(Uint8View{(const uint8_t *) rdata, rdlen}), flags);
                auto *req = (Request *) context;
                if (errorCode != kDNSServiceErr_NoError) {
                    req->error = make_error(dns_error_to_resolver_error(errorCode));
                    req->parent->complete_request(*req);
                    return;
                }

                if (rrtype == req->rr_type) {
                    req->rr_type_received = true;
                }
                ldns_rr *rr = ldns_rr_new();
                ldns_rr_set_owner(rr, ldns_dname_new_frm_str(fullname));
                ldns_rr_set_type(rr, static_cast<ldns_rr_type>(rrtype));
                ldns_rr_set_class(rr, static_cast<ldns_rr_class>(rrclass));
                ldns_rr_set_ttl(rr, ttl);
                size_t pos = 0;
                std::vector<uint8_t> r_vecdata;
                r_vecdata.resize(rdlen + 2);
                uint16_t rdlen_network = htons(rdlen);
                memcpy(r_vecdata.data(), &rdlen_network, 2);
                memcpy(r_vecdata.data() + 2, rdata, rdlen);
                ldns_status status = ldns_wire2rdf(rr, r_vecdata.data(), r_vecdata.size(), &pos);
                if (status != LDNS_STATUS_OK) {
                    req->error = make_error(SystemResolverError::AE_DECODE_ERROR, make_error(status));
                    req->parent->complete_request(*req);
                    return;
                }
                ldns_rr_list_push_rr(req->rr_list.get(), rr);

                if ((flags & kDNSServiceFlagsMoreComing) == 0) {
                    if ((flags & kDNSServiceFlagAnsweredFromCache) && !req->rr_type_received
                            && errorCode == kDNSServiceErr_NoError) {
                        tracelog(g_log, "Detected partial answer from cache, waiting more");
                        return;
                    }
                    tracelog(g_log, "Done");
                    req->parent->complete_request(*req);
                    return;
                }
                tracelog(g_log, "More coming");
            }
        };

        // The destructor resumes the coroutines awaiting their results, so they may try to resolve
        // more names. Refuse them, so that they can't modify `m_requests` while it's drained.
        if (m_destroying) {
            return Awaitable{.req = nullptr,
                    .result = make_error(SystemResolverError::AE_SHUTTING_DOWN, "The resolver is being destroyed")};
        }

        uint64_t id = m_next_request_id++;
        auto &req = m_requests[id];
        req.id = id;
        req.parent = this;
        req.domain = std::string(domain);
        req.rr_type = rr_type;

        return Awaitable{.req = &req};
    }

    void complete_request(Request &req) {
        if (req.continuation) {
            req.continuation();
        } else {
            m_requests.erase(req.id);
        }
    }

    EventLoop *m_loop = nullptr;
    uint32_t m_if_index{};     ///< The network interface index.
    bool m_destroying = false; ///< Whether the resolver is being destroyed. No new requests are accepted.
    uint64_t m_next_request_id = 0;
    std::map<uint64_t, Request> m_requests;
    Millis m_timeout;
};

SystemResolver::SystemResolver(
        ag::dns::SystemResolver::ConstructorAccess, ag::dns::EventLoop *loop, Millis timeout, uint32_t if_index) {
    m_pimpl = std::make_unique<Impl>(loop, timeout, if_index);
}

SystemResolver::~SystemResolver() = default;

ag::Result<std::unique_ptr<SystemResolver>, SystemResolverError> SystemResolver::create(
        EventLoop *loop, Millis timeout, uint32_t if_index) {
    std::unique_ptr<SystemResolver> ret =
            std::make_unique<SystemResolver>(ConstructorAccess{}, loop, timeout, if_index);
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
