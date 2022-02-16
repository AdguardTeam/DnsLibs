#import <Foundation/Foundation.h>

#import "AGDnsProxyEvents.h"

/**
 * DNS proxy error domain
 */
extern NSErrorDomain const AGDnsProxyErrorDomain;

/**
 * DNS error codes
 */
typedef NS_ENUM(NSInteger, AGDnsProxyError) {
    AGDPE_PARSE_DNS_STAMP_ERROR,
    AGDPE_TEST_UPSTREAM_ERROR,
    AGDPE_PROXY_INIT_ERROR,
    AGDPE_PROXY_INIT_LISTENER_ERROR,
    AGDPE_PROXY_INIT_WARNING,
};

/**
 * Logging levels
 */
typedef NS_ENUM(NSInteger, AGLogLevel) {
    AGLL_TRACE,
    AGLL_DEBUG,
    AGLL_INFO,
    AGLL_WARN,
    AGLL_ERR,
};

/**
 * Listener protocols
 */
typedef NS_ENUM(NSInteger, AGListenerProtocol) {
    AGLP_UDP,
    AGLP_TCP,
};

/**
 * Specifies how to respond to blocked requests.
 *
 * A request is blocked if it matches a blocking AdBlock-style rule,
 * or a blocking hosts-style rule. A blocking hosts-style rule is
 * a hosts-style rule with a loopback or all-zeroes address.
 *
 * Requests matching a hosts-style rule with an address that is
 * neither loopback nor all-zeroes are always responded
 * with the address specified by the rule.
 */
typedef NS_ENUM(NSInteger, AGBlockingMode) {
    /** Respond with REFUSED response code */
    AGBM_REFUSED,
    /** Respond with NXDOMAIN response code */
    AGBM_NXDOMAIN,
    /**
     * Respond with an address that is all-zeroes, or
     * a custom blocking address, if it is specified, or
     * an empty SOA response if request type is not A/AAAA.
     */
    AGBM_ADDRESS,
};

@interface AGLogger : NSObject

/**
 * Set the default logging level
 *
 * @param level logging level to be set
 */
+ (void) setLevel: (AGLogLevel) level;

/**
 * A function that outputs a log message.
 * The message is already formatted, including the line terminator.
 */
typedef void (^logCallback)(AGLogLevel level, const char *msg, int length);

/**
 * Set log callback
 *
 * @param func logging function
 */
+ (void) setCallback: (logCallback) func;

@end


@interface AGDnsUpstream : NSObject<NSCoding>
/**
 * A DNS server address:
 *      8.8.8.8:53 -- plain DNS
 *      tcp://8.8.8.8:53 -- plain DNS over TCP
 *      tls://1.1.1.1 -- DNS-over-TLS
 *      https://dns.adguard.com/dns-query -- DNS-over-HTTPS
 *      sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
 *      quic://dns.adguard.com:8853 -- DNS-over-QUIC
 */
@property(nonatomic, readonly) NSString *address;
/**
 * List of plain DNS servers to be used to resolve DOH/DOT hostnames (if any)
 */
@property(nonatomic, readonly) NSArray<NSString *> *bootstrap;
/**
 * Default upstream timeout in milliseconds. Also used as a timeout for bootstrap DNS requests.
 * timeout = 0 means infinite timeout.
 */
@property(nonatomic, readonly) NSInteger timeoutMs;
/**
 * Resolver's IP address. In the case if it's specified,
 * bootstrap DNS servers won't be used at all.
 */
@property(nonatomic, readonly) NSData *serverIp;
/**
 * User-provided ID for this upstream
 */
@property(nonatomic, readonly) NSInteger id;
/**
 * Name of the network interface to route traffic through, nil is default
 */
@property(nonatomic, readonly) NSString *outboundInterfaceName;

- (instancetype) initWithAddress: (NSString *) address
        bootstrap: (NSArray<NSString *> *) bootstrap
        timeoutMs: (NSInteger) timeoutMs
        serverIp: (NSData *) serverIp
        id: (NSInteger) id
        outboundInterfaceName: (NSString *) outboundInterfaceName;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

@end

@interface AGDns64Settings : NSObject<NSCoding>

/**
 * The upstream to use for discovery of DNS64 prefixes
 */
@property(nonatomic, readonly) NSArray<AGDnsUpstream *> *upstreams;

/**
 * How many times, at most, to try DNS64 prefixes discovery before giving up
 */
@property(nonatomic, readonly) NSInteger maxTries;

/**
 * How long to wait before a dns64 prefixes discovery attempt, in milliseconds
 */
@property(nonatomic, readonly) NSInteger waitTimeMs;

- (instancetype) initWithUpstreams: (NSArray<AGDnsUpstream *> *) upstreams
            maxTries: (NSInteger) maxTries
            waitTimeMs: (NSInteger) waitTimeMs;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

@end

@interface AGListenerSettings : NSObject<NSCoding>

/**
 * The address to listen on
 */
@property(nonatomic, readonly) NSString *address;

/**
 * The port to listen on
 */
@property(nonatomic, readonly) NSInteger port;

/**
 * The protocol to listen for
 */
@property(nonatomic, readonly) AGListenerProtocol proto;

/**
 * Don't close the TCP connection after sending the first response
 */
@property(nonatomic, readonly) BOOL persistent;

/**
 * Close the TCP connection this long after the last request received, in milliseconds
 */
@property(nonatomic, readonly) NSInteger idleTimeoutMs;

- (instancetype) initWithAddress: (NSString *) address
                            port: (NSInteger) port
                           proto: (AGListenerProtocol) proto
                      persistent: (BOOL) persistent
                   idleTimeoutMs: (NSInteger) idleTimeoutMs;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

@end

/**
 * Outbound proxy protocols
 */
typedef NS_ENUM(NSInteger, AGOutboundProxyProtocol) {
    AGOPP_HTTP_CONNECT, // Plain HTTP proxy
    AGOPP_HTTPS_CONNECT, // HTTPs proxy
    AGOPP_SOCKS4, // Socks4 proxy
    AGOPP_SOCKS5, // Socks5 proxy without UDP support
    AGOPP_SOCKS5_UDP, // Socks5 proxy with UDP support
};

@interface AGOutboundProxyAuthInfo : NSObject<NSCoding>
/** User name for authentication */
@property(nonatomic, readonly) NSString *username;
/** Password for authentication */
@property(nonatomic, readonly) NSString *password;

- (instancetype) initWithUsername: (NSString *)username
                         password: (NSString *)password;

- (instancetype) init NS_UNAVAILABLE;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

@end

@interface AGOutboundProxySettings : NSObject<NSCoding>
/** The proxy protocol */
@property(nonatomic, readonly) AGOutboundProxyProtocol protocol;
/** The proxy server address (must be a valid IP address) */
@property(nonatomic, readonly) NSString *address;
/** The proxy server port */
@property(nonatomic, readonly) NSInteger port;
/** The authentication information (if nil, authentication is not performed) */
@property(nonatomic, readonly) AGOutboundProxyAuthInfo *authInfo;
/** If true and the proxy connection is secure, the certificate won't be verified */
@property(nonatomic, readonly) BOOL trustAnyCertificate;

- (instancetype) initWithProtocol: (AGOutboundProxyProtocol)protocol
                          address: (NSString *)address
                             port: (NSInteger)port
                         authInfo: (AGOutboundProxyAuthInfo *)authInfo
              trustAnyCertificate: (BOOL)trustAnyCertificate;

- (instancetype) init NS_UNAVAILABLE;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

@end

@interface AGDnsFilterParams : NSObject<NSCoding>
/**
 * Filter identifier
 */
@property(nonatomic, readonly) NSInteger id;
/**
 * Filter data
 * Either path to file with rules, or rules as a string
 */
@property(nonatomic, readonly) NSString *data;
/**
 * If YES, data is rules, otherwise data is path to file with rules
 */
@property(nonatomic, readonly) BOOL inMemory;

- (instancetype) initWithId:(NSInteger)id
                       data:(NSString *)data
                   inMemory:(BOOL)inMemory;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

@end

@interface AGDnsProxyConfig : NSObject<NSCoding>
/**
 * Upstreams settings
 */
@property(nonatomic, readonly) NSArray<AGDnsUpstream *> *upstreams;
/**
 * Fallback upstreams settings
 */
@property(nonatomic, readonly) NSArray<AGDnsUpstream *> *fallbacks;
/**
 * Requests for these domains will be forwarded directly to the fallback upstreams, if there are any.
 * A wildcard character, `*`, which stands for any number of characters, is allowed to appear multiple
 * times anywhere except at the end of the domain (which implies that a domain consisting only of
 * wildcard characters is invalid).
 */
@property(nonatomic, readonly) NSArray<NSString *> *fallbackDomains;
/**
 * If enabled, DNS search domains will be automatically appended to the fallback domains,
 * allowing to forward requests for, e.g., *.local, directly to the fallback upstreams.
 */
@property(nonatomic, readonly) BOOL detectSearchDomains;
/**
 * Filters
 */
@property(nonatomic, readonly) NSArray<AGDnsFilterParams *> *filters;
#if TARGET_OS_IPHONE
/**
 * If not zero, the filtering engine might not load some rules from the configured
 * filters to try to keep the estimated memory usage below this limit.
 * If any rules are not loaded because of this limit, a warning will be returned
 * from `[AGDnsProxy initWithConfig:]`.
 */
@property(nonatomic, readonly) NSUInteger filtersMemoryLimitBytes;
#endif // TARGET_OS_IPHONE
/**
 * TTL of the record for the blocked domains (in seconds)
 */
@property(nonatomic, readonly) NSInteger blockedResponseTtlSecs;
/**
 * DNS64 settings. If nil, DNS64 is disabled
 */
@property(nonatomic, readonly) AGDns64Settings *dns64Settings;
/**
 * List of addresses/ports/protocols/etc... to listen on
 */
@property(nonatomic, readonly) NSArray<AGListenerSettings *> *listeners;
/**
 * Outbound proxy settings
 */
@property(nonatomic, readonly) AGOutboundProxySettings *outboundProxy;
/**
 * If false, bootstrappers will fetch only A records.
 */
@property(nonatomic, readonly) BOOL ipv6Available;
/**
 * Block AAAA requests.
 */
@property(nonatomic, readonly) BOOL blockIpv6;
/**
 * How to respond to requests blocked by AdBlock-style rules
 */
@property(nonatomic, readonly) AGBlockingMode adblockRulesBlockingMode;
/**
 * How to respond to requests blocked by hosts-style rules
 */
@property(nonatomic, readonly) AGBlockingMode hostsRulesBlockingMode;
/**
 * Custom IPv4 address to return for filtered requests
 */
@property(nonatomic, readonly) NSString *customBlockingIpv4;
/**
 * Custom IPv6 address to return for filtered requests
 */
@property(nonatomic, readonly) NSString *customBlockingIpv6;
/**
 * Maximum number of cached responses
 */
@property(nonatomic, readonly) NSUInteger dnsCacheSize;
/**
 * Enable optimistic DNS caching
 */
@property(nonatomic, readonly) BOOL optimisticCache;
/**
 * Enable DNSSEC OK extension.
 * This options tells server that we want to receive DNSSEC records along with normal queries.
 * If they exist, request processed event will have DNSSEC flag on.
 * WARNING: may increase data usage and probability of TCP fallbacks.
 */
@property(nonatomic, readonly) BOOL enableDNSSECOK;
/**
 * If enabled, detect retransmitted requests and handle them using fallback upstreams only.
 */
@property(nonatomic, readonly) BOOL enableRetransmissionHandling;
/**
 * Path to adguard-tun-helper (macOS only)
 */
@property(nonatomic, readonly) NSString *helperPath;

- (instancetype) initWithUpstreams: (NSArray<AGDnsUpstream *> *) upstreams
        fallbacks: (NSArray<AGDnsUpstream *> *) fallbacks
        fallbackDomains: (NSArray<NSString *> *) fallbackDomains
        detectSearchDomains: (BOOL) detectSearchDomains
        filters: (NSArray<AGDnsFilterParams *> *) filters
#if TARGET_OS_IPHONE
        filtersMemoryLimitBytes: (NSUInteger) filtersMemoryLimitBytes
#endif // TARGET_OS_IPHONE
        blockedResponseTtlSecs: (NSInteger) blockedResponseTtlSecs
        dns64Settings: (AGDns64Settings *) dns64Settings
        listeners: (NSArray<AGListenerSettings *> *) listeners
        outboundProxy: (AGOutboundProxySettings *) outboundProxy
        ipv6Available: (BOOL) ipv6Available
        blockIpv6: (BOOL) blockIpv6
        adblockRulesBlockingMode: (AGBlockingMode) adblockRulesBlockingMode
        hostsRulesBlockingMode: (AGBlockingMode) hostsRulesBlockingMode
        customBlockingIpv4: (NSString *) customBlockingIpv4
        customBlockingIpv6: (NSString *) customBlockingIpv6
        dnsCacheSize: (NSUInteger) dnsCacheSize
        optimisticCache: (BOOL) optimisticCache
        enableDNSSECOK: (BOOL) enableDNSSECOK
        enableRetransmissionHandling: (BOOL) enableRetransmissionHandling
        helperPath: (NSString *)helperPath;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

/**
 * @brief Get default DNS proxy settings
 */
+ (instancetype) getDefault;
@end


@interface AGDnsProxy : NSObject
/**
 * @brief Initialize DNS proxy with the given configuration
 *
 * @param config proxy configuration
 * @param events proxy events handler
 * @param error  error reference
 */
- (instancetype) initWithConfig: (AGDnsProxyConfig *) config
                        handler: (AGDnsProxyEvents *) events
                          error: (NSError **) error NS_SWIFT_NOTHROW;

/**
 * @brief Process UDP/TCP packet payload
 *
 * @param packet data to process
 * @return Response packet payload, or
 *         nil if nothing shoud be sent in response
 */
- (NSData *) handlePacket: (NSData *) packet;

/**
 * Stop DnsProxy. Should be called before dealloc.
 */
- (void) stop;

/**
* Check if string is a valid rule
* @param str string to check
* @return true if string is a valid rule, false otherwise
*/
+ (BOOL) isValidRule: (NSString *) str;

/**
 * Return the DNS proxy library version.
 */
+ (NSString *) libraryVersion;
@end

typedef NS_ENUM(NSInteger, AGStampProtoType) {
    /** plain is plain DNS */
    AGSPT_PLAIN,
    /** dnscrypt is DNSCrypt */
    AGSPT_DNSCRYPT,
    /** doh is DNS-over-HTTPS */
    AGSPT_DOH,
    /** tls is DNS-over-TLS */
    AGSPT_TLS,
    /** doq is DNS-over-QUIC */
    AGSPT_DOQ,
};

@interface AGDnsStamp : NSObject<NSCoding>
/**
 * Protocol
 */
@property(nonatomic) AGStampProtoType proto;
/**
 * Server address
 */
@property(nonatomic) NSString *serverAddr;
/**
 * Provider name
 */
@property(nonatomic) NSString *providerName;
/**
 * Path (for DOH)
 */
@property(nonatomic) NSString *path;
/**
 * The DNSCrypt provider’s Ed25519 public key, as 32 raw bytes. Empty for other types.
 */
@property(nonatomic) NSData *serverPublicKey;
/**
 * Hash is the SHA256 digest of one of the TBS certificate found in the validation chain, typically
 * the certificate used to sign the resolver’s certificate. Multiple hashes can be provided for seamless
 * rotations.
 */
@property(nonatomic) NSArray<NSData *> *hashes;

/** Server properties */
/** Resolver does DNSSEC validation */
@property(nonatomic) BOOL dnssec;
/** Resolver does not record logs */
@property(nonatomic) BOOL noLog;
/** Resolver doesn't intentionally block domains */
@property(nonatomic) BOOL noFilter;

- (instancetype) init NS_UNAVAILABLE;

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

/** Init a stamp from "sdns://" string */
- (instancetype) initWithString:(NSString *)stampStr error:(NSError **)error NS_SWIFT_NOTHROW;

/** Create a stamp from "sdns://" string */
+ (instancetype) stampWithString:(NSString *)stampStr error:(NSError **)error NS_SWIFT_NOTHROW;

/** A URL representation of this stamp which can be used as a valid AGDnsUpstream address */
@property(nonatomic, readonly) NSString *prettyUrl;

/** A URL representation of this stamp which is prettier, but can NOT be used as a valid AGDnsUpstream address */
@property(nonatomic, readonly) NSString *prettierUrl;

/** An "sdns://" string representation */
@property(nonatomic, readonly) NSString *stringValue;

@end

@interface AGDnsUtils : NSObject

/**
 * Checks if upstream is valid and available
 * @param opts Upstream options
 * @param ipv6Available Whether IPv6 is available (if true, bootstrapper is allowed to make AAAA queries)
 * @param offline Don't perform online upstream check
 * @return If it is, no error is returned. Otherwise this method returns an error with an explanation.
 */
+ (NSError *) testUpstream: (AGDnsUpstream *) opts ipv6Available: (BOOL) ipv6Available offline: (BOOL) offline;

@end
