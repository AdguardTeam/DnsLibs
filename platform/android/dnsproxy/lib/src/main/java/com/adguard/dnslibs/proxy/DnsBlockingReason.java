package com.adguard.dnslibs.proxy;

/**
 * DNS blocking reason
 */
public enum DnsBlockingReason {
    /** Not blocked */
    NONE,
    /** Mozilla DoH detection */
    MOZILLA_DOH_DETECTION,
    /** DDR blocking */
    DDR,
    /** IPv6 blocking */
    IPV6,
    /** Query matched by rule */
    QUERY_MATCHED_BY_RULE,
    /** CNAME matched by rule */
    CNAME_MATCHED_BY_RULE,
    /** IP matched by rule */
    IP_MATCHED_BY_RULE,
    /** HTTPS matched by rule */
    HTTPS_MATCHED_BY_RULE
}
