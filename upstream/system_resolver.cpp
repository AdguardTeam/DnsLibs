#include <future>

#include <fmt/format.h>

#include "system_resolver.h"
#include "dns/common/event_loop.h"
#include <dns_sd.h>

namespace ag::dns {

static ag::Logger g_log{"SystemResolver"};

class SystemResolver::Impl {
public:
    Impl(EventLoop *loop, uint32_t if_index)
            : m_loop(loop)
            , m_if_index(if_index) {
        m_queue = dispatch_queue_create("DnsLibs.SystemResolver", DISPATCH_QUEUE_SERIAL);
    }

    ~Impl() {
        dispatch_release(m_queue);
    }

    auto resolve(std::string_view domain, ldns_rr_type rr_type) {
        struct Awaitable {
            Impl *parent;
            EventLoop *loop;
            std::mutex mutex;
            std::string domain;
            ldns_rr_type rr_type;
            bool rr_type_received;
            SystemResolver::LdnsRrListPtr rr_list{ldns_rr_list_new()};
            Error<SystemResolverError> error;
            ServiceRefPtr service;
            bool done;
            std::coroutine_handle<> caller;

            auto await_ready() {
                std::scoped_lock l{mutex};
                DNSServiceRef service_ref;

                auto error_code = DNSServiceQueryRecord(&service_ref,
                        kDNSServiceFlagsUnicastResponse | kDNSServiceFlagsReturnIntermediates
                                | kDNSServiceFlagAnsweredFromCache,
                        parent->m_if_index, domain.data(), rr_type, kDNSServiceClass_IN, handle_dns_service_query_record_reply, this);

                if (error_code != kDNSServiceErr_NoError) {
                    error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
                    return true;
                }
                tracelog(g_log, "Requested domain {} rrtype {}",
                        domain, AllocatedPtr<char>{ldns_rr_type2str(ldns_rr_type(rr_type))}.get() ?: AG_FMT("TYPE{}", (int)rr_type));
                DNSServiceSetDispatchQueue(service_ref, parent->m_queue);
                service.reset(service_ref);

                return false;
            }

            auto await_suspend(std::coroutine_handle<> h) {
                std::scoped_lock l{mutex};
                if (done) {
                    h();
                } else {
                    caller = h;
                }
            }

            Result<SystemResolver::LdnsRrListPtr, SystemResolverError> await_resume() {
                if (error) {
                    return error;
                } else {
                    return std::move(rr_list);
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
            static void handle_dns_service_query_record_reply(DNSServiceRef sdRef, DNSServiceFlags flags,
                    uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *fullname, uint16_t rrtype,
                    uint16_t rrclass, uint16_t rdlen, const void *rdata, uint32_t ttl, void *context) {
                tracelog(g_log, "Reply: error {}, {} {} {} {} {}, flags {:x}",
                        errorCode, fullname ?: "(null)",
                        ttl,
                        AllocatedPtr<char>{ldns_rr_class2str(ldns_rr_class(rrclass))}.get() ?: AG_FMT("CLASS{}", rrclass),
                        AllocatedPtr<char>{ldns_rr_type2str(ldns_rr_type(rrtype))}.get() ?: AG_FMT("TYPE{}", rrtype),
                        utils::encode_to_hex(Uint8View{(const uint8_t *) rdata, rdlen}), flags);
                auto *self = (Awaitable *) context;
                std::scoped_lock l{self->mutex};
                if (errorCode == kDNSServiceErr_NoError) {
                    if (rrtype == self->rr_type) {
                        self->rr_type_received = true;
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
                        self->error = make_error(SystemResolverError::AE_DECODE_ERROR, make_error(status));
                    }
                    ldns_rr_list_push_rr(self->rr_list.get(), rr);
                } else {
                    if (errorCode == kDNSServiceErr_NoSuchRecord) {
                        self->error = make_error(SystemResolverError::AE_RECORD_NOT_FOUND);
                    } else if (errorCode == kDNSServiceErr_NoSuchName) {
                        self->error = make_error(SystemResolverError::AE_DOMAIN_NOT_FOUND);
                    } else {
                        self->error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
                    }
                }

                if ((flags & kDNSServiceFlagsMoreComing) == 0) {
                    if ((flags & kDNSServiceFlagAnsweredFromCache) && !self->rr_type_received
                            && errorCode == kDNSServiceErr_NoError) {
                        tracelog(g_log, "Detected partial answer from cache, waiting more");
                        return;
                    }
                    tracelog(g_log, "Done");
                    self->done = true;
                    self->service.reset();
                    self->loop->submit(self->caller);
                    return;
                }
                tracelog(g_log, "More coming");
            }
        };
        return Awaitable{
                .parent = this,
                .loop = m_loop,
                .domain = std::string(domain),
                .rr_type = rr_type,
        };
    }

    using ServiceRefPtr = ag::UniquePtr<std::remove_pointer_t<DNSServiceRef>, &DNSServiceRefDeallocate>;

    EventLoop *m_loop = nullptr;
    uint32_t m_if_index{}; ///< The network interface index.
    dispatch_queue_t m_queue;
};

SystemResolver::SystemResolver(ag::dns::SystemResolver::ConstructorAccess, ag::dns::EventLoop *loop, uint32_t if_index) {
    m_pimpl = std::make_unique<Impl>(loop, if_index);
}

SystemResolver::~SystemResolver() = default;

ag::Result<std::unique_ptr<SystemResolver>, SystemResolverError> SystemResolver::create(EventLoop *loop, uint32_t if_index) {
    std::unique_ptr<SystemResolver> ret = std::make_unique<SystemResolver>(ConstructorAccess{}, loop, if_index);
    if (!ret || !ret->m_pimpl) {
        return make_error(SystemResolverError::AE_INIT_ERROR);
    }
    return ret;
}

coro::Task<Result<SystemResolver::LdnsRrListPtr, SystemResolverError>>
SystemResolver::resolve(std::string_view domain, ldns_rr_type rr_type) {
    co_return co_await m_pimpl->resolve(domain, rr_type);
}


} // namespace ag::dns
