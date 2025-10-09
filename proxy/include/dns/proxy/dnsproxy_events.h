#pragma once


#include <string>
#include <functional>
#include <cstdint>
#include <vector>
#include <optional>
#include "dns/net/application_verifier.h"
#include "dns/net/socket.h"

namespace ag::dns {


/**
 * DNS request processed event
 */
struct DnsRequestProcessedEvent {
    std::string domain; /**< Queried domain name */
    std::string type; /**< Query type */
    /** Time when dnsproxy started processing request (epoch in milliseconds) */
    int64_t start_time = duration_cast<Millis>(SystemClock::now().time_since_epoch()).count();
    int32_t elapsed = 0; /**< Time elapsed on processing (in milliseconds) */
    std::string status; /**< DNS answer's status */
    std::string answer; /**< DNS Answers string representation */
    std::string original_answer; /**< If blocked by CNAME, here will be DNS original answer's string representation */
    std::optional<int32_t> upstream_id; /** ID of the upstream that provided this answer */
    int32_t bytes_sent = 0; /**< Number of bytes sent to a server */
    int32_t bytes_received = 0; /**< Number of bytes received from a server */
    std::vector<std::string> rules; /**< Filtering rules texts */
    std::vector<int32_t> filter_list_ids; /**< Filter lists IDs of corresponding rules */
    bool whitelist = false; /**< True if filtering rule is whitelist */
    std::string error; /**< If not empty, contains the error text (occurred while processing the DNS query) */
    bool cache_hit = false; /**< True if this response was served from the cache */
    bool dnssec = false; /**< True if this response has DNSSEC rrsig */
};

/**
 * Set of DNS proxy events
 */
struct DnsProxyEvents {
    /**
     * Raised right after a request is processed.
     * Notes:
     *  - if there are several upstreams in proxy configuration, the proxy tries each one
     *    consequently until it gets successful status, so in this case each failed upstream
     *    fires the event - i.e., several events will be raised for the request
     */
    std::function<void(DnsRequestProcessedEvent)> on_request_processed;
    /**
     * Raised when some transaction needs to verify a server certificate.
     * Notes:
     *  - if not provided, default verifier will be used
     */
    OnCertificateVerificationFn on_certificate_verification;
    /**
     * Provides an implementation of route-loop protection for socket.
     * This is an alternative way for case when providing UpstreamSettings.outbound_interface is not enough.
     * Notes:
     *  - if not provided, no socket protection is applied
     *  - called for every outbound socket before connect
     *  - if returns an error, the connection will fail
     */
    std::function<Error<SocketError>(evutil_socket_t, const SocketAddress &)> on_protect_socket;
};


} // namespace ag::dns
