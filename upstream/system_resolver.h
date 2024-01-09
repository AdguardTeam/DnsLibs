#pragma once

#include "common/defs.h"
#include "common/error.h"
#include "common/coro.h"
#include "dns/common/event_loop.h"

#include <cassert>
#include <dns_sd.h>
#include <ldns/ldns.h>
#include <string_view>

namespace ag::dns {

enum class SystemResolverError {
    AE_OK,                   // No error occurred
    AE_DOMAIN_NOT_FOUND,     // The specified name/record does not exist
    AE_SYSTEM_RESOLVE_ERROR, // Other errors from DNSService
    AE_DECODE_ERROR,         // Errors from ldns
    AE_INIT_ERROR            // DNSServiceRef could not be created
};

/**
 * The SystemResolver class is used for resolving DNS records using the system resolver.
 */
class SystemResolver {
    struct ConstructorAccess {};

public:
    /**
     * Unique pointer to a list of ldns_rr_list resource records.
     */
    using LdnsRrListPtr = ag::UniquePtr<ldns_rr_list, &ldns_rr_list_deep_free>;

    /**
     * Constructs a SystemResolver for a specific network interface.
     * @param if_index Index of the network interface (default is 0, which means any interface).
     */
    SystemResolver(ConstructorAccess, EventLoop *loop, uint32_t if_index = 0);
    static Result<std::unique_ptr<SystemResolver>, SystemResolverError> create(EventLoop *loop, uint32_t if_index);

    struct ResolveAwaitable {
        void *context;
        bool await_ready();
        void await_suspend(std::coroutine_handle<> h);
        Result<LdnsRrListPtr, SystemResolverError> await_resume();
    };
    /**
     * Resolves a domain to a list of resource records.
     * @param domain Domain to resolve.
     * @param rr_type Type of the resource record to resolve.
     * @return A unique pointer to a list of resource records.
     */
    ResolveAwaitable resolve(std::string_view domain, ldns_rr_type rr_type);

    using ServiceRefPtr = ag::UniquePtr<std::remove_pointer_t<DNSServiceRef>, &DNSServiceRefDeallocate>;

private:
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
            uint16_t rrclass, uint16_t rdlen, const void *rdata, uint32_t ttl, void *context);


    EventLoop *m_loop = nullptr;
    uint32_t m_if_index{}; ///< The network interface index.
    DNSServiceErrorType m_error_code = 0;
    ServiceRefPtr m_service_ref{};
    dispatch_queue_t m_queue;
};

} // namespace ag::dns

namespace ag {
template <>
struct ErrorCodeToString<dns::SystemResolverError> {
    const char *operator()(dns::SystemResolverError e) {
        switch (e) {
        case dns::SystemResolverError::AE_OK:
            return "No error";
        case dns::SystemResolverError::AE_DOMAIN_NOT_FOUND:
            return "No such name or record";
        case dns::SystemResolverError::AE_DECODE_ERROR:
            return "LDNS error";
        case dns::SystemResolverError::AE_INIT_ERROR:
            return "DNSServiceRef could not be created";
        case dns::SystemResolverError::AE_SYSTEM_RESOLVE_ERROR:
            return "Other errors from DNSService";
        }
    }
};

template<>
struct ErrorCodeToString<ldns_status> {
    const char *operator()(ldns_status e) {
        const char *error_str = ldns_get_errorstr_by_id(e);
        return error_str ? error_str : "Unknown error";
    }
};
} // namespace ag
