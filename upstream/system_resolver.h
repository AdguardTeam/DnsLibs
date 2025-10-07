#pragma once

#include "common/defs.h"
#include "common/error.h"
#include "common/coro.h"
#include "dns/common/event_loop.h"

#include <cassert>
#include <ldns/ldns.h>
#include <string_view>

#ifdef __ANDROID__
#include <android/multinetwork.h>
#endif

namespace ag::dns {

enum class SystemResolverError {
    AE_OK,                   // No error occurred
    AE_RECORD_NOT_FOUND,     // The specified record does not exist
    AE_DOMAIN_NOT_FOUND,     // The specified name does not exist
    AE_SYSTEM_RESOLVE_ERROR, // Other errors from system resolver
    AE_DECODE_ERROR,         // Errors from ldns
    AE_INIT_ERROR,           // System resolver could not be created
    AE_SHUTTING_DOWN,        // Shutting down
    AE_TIMED_OUT,            // Timed out
};

/**
 * The SystemResolver class is used for resolving DNS records using the system resolver.
 * Platform-specific implementations are provided for Apple (DNSService) and Android (android_res_*).
 */
class SystemResolver {
    struct ConstructorAccess {};

public:
    /**
     * Unique pointer to a list of ldns_rr_list resource records.
     */
    using LdnsRrListPtr = ag::UniquePtr<ldns_rr_list, &ldns_rr_list_deep_free>;

#ifdef __ANDROID__
    /**
     * Constructs a SystemResolver for a specific Android network.
     * @param network_handle Android network handle (default is NETWORK_UNSPECIFIED).
     */
    SystemResolver(ConstructorAccess, EventLoop *loop, Millis timeout, net_handle_t network_handle = NETWORK_UNSPECIFIED);
    static Result<std::unique_ptr<SystemResolver>, SystemResolverError> create(EventLoop *loop, Millis timeout, net_handle_t network_handle);
#else
    /**
     * Constructs a SystemResolver for a specific network interface.
     * @param if_index Index of the network interface (default is 0, which means any interface).
     */
    SystemResolver(ConstructorAccess, EventLoop *loop, Millis timeout, uint32_t if_index = 0);
    static Result<std::unique_ptr<SystemResolver>, SystemResolverError> create(EventLoop *loop, Millis timeout, uint32_t if_index);
#endif

    ~SystemResolver();

    /**
     * Resolves a domain to a list of resource records.
     * @param domain Domain to resolve.
     * @param rr_type Type of the resource record to resolve.
     * @return A unique pointer to a list of resource records.
     */
    coro::Task<Result<LdnsRrListPtr, SystemResolverError>>
    resolve(std::string_view domain, ldns_rr_type rr_type);

private:
    class Impl;
    std::unique_ptr<Impl> m_pimpl;
};

} // namespace ag::dns

namespace ag {
template <>
struct ErrorCodeToString<dns::SystemResolverError> {
    const char *operator()(dns::SystemResolverError e) {
        switch (e) {
        case dns::SystemResolverError::AE_OK:
            return "No error";
        case dns::SystemResolverError::AE_RECORD_NOT_FOUND:
            return "No such record";
        case dns::SystemResolverError::AE_DOMAIN_NOT_FOUND:
            return "No such name";
        case dns::SystemResolverError::AE_DECODE_ERROR:
            return "LDNS error";
        case dns::SystemResolverError::AE_INIT_ERROR:
            return "System resolver could not be created";
        case dns::SystemResolverError::AE_SHUTTING_DOWN:
            return "Shutting down";
        case dns::SystemResolverError::AE_TIMED_OUT:
            return "Timed out";
        case dns::SystemResolverError::AE_SYSTEM_RESOLVE_ERROR:
            return "Other errors from system resolver";
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
