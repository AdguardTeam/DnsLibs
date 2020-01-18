#pragma once


#include <string>
#include <functional>
#include <cstdint>
#include <vector>
#include <optional>


namespace ag {


/**
 * DNS request processed event
 */
struct dns_request_processed_event {
    std::string domain; /**< Queried domain name */
    std::string type; /**< Query type */
    int64_t start_time; /**< Time when dnsproxy started processing request (epoch in milliseconds) */
    int elapsed; /**< Time elapsed on processing (in milliseconds) */
    std::string status; /**< DNS answer's status */
    std::string answer; /**< DNS Answers string representation */
    std::string original_answer; /**< If blocked by CNAME, here will be DNS original answer's string representation */
    std::string upstream_addr; /**< Address of the upstream used to resolve */
    int bytes_sent; /**< Number of bytes sent to a server */
    int bytes_received; /**< Number of bytes received from a server */
    std::vector<std::string> rules; /**< Filtering rules texts */
    std::vector<int> filter_list_ids; /**< Filter lists IDs of corresponding rules */
    bool whitelist; /**< True if filtering rule is whitelist */
    std::string error; /**< If not empty, contains the error text (occurred while processing the DNS query) */
    bool cache_hit; /**<Whether this response was served from the cache */
};

/**
 * Certificate verification event
 */
struct certificate_verification_event {
    std::vector<uint8_t> certificate; /** certificate being verified */
    std::vector<std::vector<uint8_t>> chain; /** certificate chain */
};

/**
 * Set of DNS proxy events
 */
struct dnsproxy_events {
    /**
     * Raised right after a request is processed.
     * Notes:
     *  - if there are several upstreams in proxy configuration, the proxy tries each one
     *    consequently until it gets successful status, so in this case each failed upstream
     *    fires the event - i.e., several events will be raised for the request
     */
    std::function<void(dns_request_processed_event)> on_request_processed;
    /**
     * Raised when some transaction needs to verify a server certificate.
     * Notes:
     *  - if not provided, default verifier will be used
     */
    std::function<std::optional<std::string>(certificate_verification_event)> on_certificate_verification;
};


}
