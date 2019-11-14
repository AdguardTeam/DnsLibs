#pragma once


#include <string>
#include <functional>
#include <cstdint>
#include <vector>


namespace ag {


/**
 * DNS request processed event
 */
struct dns_request_processed_event {
    std::string domain; /**< Queried domain name */
    std::string type; /**< Query type */
    int64_t start_time; /**< Time when dnsproxy started processing request (epoch in milliseconds) */
    int elapsed; /**< Time elapsed on processing (in milliseconds) */
    std::string answer; /**< DNS Answers string representation */
    std::string upstream_addr; /**< Address of the upstream used to resolve */
    int bytes_sent; /**< Number of bytes sent to a server */
    int bytes_received; /**< Number of bytes received from a server */
    std::vector<std::string> rules; /**< Filtering rules texts */
    std::vector<int> filter_list_ids; /**< Filter lists IDs of corresponding rules */
    bool whitelist; /**< True if filtering rule is whitelist */
    std::string error; /**< If not empty, contains the error text (occurred while processing the DNS query) */
};

/**
 * Set of DNS proxy events
 */
struct dnsproxy_events {
    /** Raised right after a request was processed */
    std::function<void(dns_request_processed_event)> on_request_processed;
};


}
