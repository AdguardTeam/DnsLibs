#include <future>

#include <fmt/format.h>

#include "system_resolver.h"
#include "dns/common/event_loop.h"

namespace ag::dns {

SystemResolver::SystemResolver(ConstructorAccess, EventLoop *loop, uint32_t if_index)
        : m_loop(loop)
        , m_if_index(if_index) {
    DNSServiceRef service_ref = nullptr;
    DNSServiceErrorType error_code = DNSServiceCreateConnection(&service_ref);
    if (error_code != kDNSServiceErr_NoError) {
        m_error_code = error_code;
    }
    m_service_ref.reset(service_ref);
    m_queue = dispatch_queue_create("SystemResolver", DISPATCH_QUEUE_SERIAL);
    DNSServiceSetDispatchQueue(m_service_ref.get(), m_queue);
}

ag::Result<std::unique_ptr<SystemResolver>, SystemResolverError> SystemResolver::create(EventLoop *loop, uint32_t if_index) {
    std::unique_ptr<SystemResolver> ret = std::make_unique<SystemResolver>(ConstructorAccess{}, loop, if_index);
    if (ret && ret->m_error_code != 0) {
        return make_error(SystemResolverError{ret->m_error_code});
    }
    return ret;
}

struct Context {
    EventLoop *loop;
    std::mutex mutex;
    ldns_rr_type rr_type;
    bool rr_type_received;
    SystemResolver::LdnsRrListPtr rr_list{ldns_rr_list_new()};
    Error<SystemResolverError> error;
    SystemResolver::ServiceRefPtr service;
    bool done;
    std::coroutine_handle<> caller;
};

bool SystemResolver::ResolveAwaitable::await_ready() {
    Context &ctx = *(Context *)context;
    std::scoped_lock l{ctx.mutex};
    return ctx.done;
}

void SystemResolver::ResolveAwaitable::await_suspend(std::coroutine_handle<> h) {
    Context &ctx = *(Context *)context;
    std::scoped_lock l{ctx.mutex};
    if (ctx.done) {
        h();
    } else {
        ctx.caller = h;
    }
}

Result<SystemResolver::LdnsRrListPtr, SystemResolverError> SystemResolver::ResolveAwaitable::await_resume() {
    Context &ctx = *(Context *)context;
    Result<SystemResolver::LdnsRrListPtr, SystemResolverError> ret;
    if (ctx.error) {
        ret = ctx.error;
    } else {
        ret = std::move(ctx.rr_list);
    }
    delete (Context *) context;
    return ret;
}

SystemResolver::ResolveAwaitable SystemResolver::resolve(
        std::string_view domain, ldns_rr_type rr_type) {
    ResolveAwaitable awaitable{};
    awaitable.context = new Context{};
    Context &context = *(Context *)awaitable.context;
    context.loop = m_loop;
    context.rr_type = rr_type;
    std::unique_lock l{context.mutex};
    DNSServiceRef service_ref = m_service_ref.get();

    auto error_code = DNSServiceQueryRecord(&service_ref,
            kDNSServiceFlagsUnicastResponse | kDNSServiceFlagsReturnIntermediates | kDNSServiceFlagsShareConnection
                    | kDNSServiceFlagAnsweredFromCache,
            m_if_index, domain.data(), rr_type, kDNSServiceClass_IN, handle_dns_service_query_record_reply, &context);

    if (error_code != kDNSServiceErr_NoError) {
        context.error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
        context.done = true;
    }
    context.service.reset(service_ref);
    return awaitable;
}

void SystemResolver::handle_dns_service_query_record_reply(DNSServiceRef sdRef, DNSServiceFlags flags,
        uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *fullname, uint16_t rrtype, uint16_t rrclass,
        uint16_t rdlen, const void *rdata, uint32_t ttl, void *arg) {
    auto *context = static_cast<Context *>(arg);
    std::scoped_lock l{context->mutex};
    if (errorCode == kDNSServiceErr_NoError) {
        if (rrtype == context->rr_type) {
            context->rr_type_received = true;
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
            context->error = make_error(SystemResolverError::AE_DECODE_ERROR, make_error(status));
        }
        ldns_rr_list_push_rr(context->rr_list.get(), rr);
    } else {
        if (errorCode == kDNSServiceErr_NoSuchRecord || errorCode == kDNSServiceErr_NoSuchName) {
            context->error = make_error(SystemResolverError::AE_DOMAIN_NOT_FOUND);
        } else {
            context->error = make_error(SystemResolverError::AE_SYSTEM_RESOLVE_ERROR);
        }
    }

    if ((flags & kDNSServiceFlagsMoreComing) == 0) {
        if ((flags & kDNSServiceFlagAnsweredFromCache) && !context->rr_type_received
                && errorCode == kDNSServiceErr_NoError) {
            return;
        }
        context->done = true;
        context->service.reset();
        context->loop->submit(context->caller);
    }
}

} // namespace ag::dns
