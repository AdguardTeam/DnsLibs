#import <Foundation/Foundation.h>

#import "AGDnsXPCObject.h"

/**
 * @interface AGDnsRequestProcessedEvent
 * DNS request processed event.
 */
@interface AGDnsRequestProcessedEvent : AGDnsXPCObject<NSSecureCoding>
@property(nonatomic) NSString *domain; /**< Queried domain name */
@property(nonatomic) NSString *type; /**< Query type */
@property(nonatomic) NSInteger startTime; /**< Time when dnsproxy started processing request (epoch in milliseconds) */
@property(nonatomic) NSInteger elapsed; /**< Time elapsed on processing (in milliseconds) */
@property(nonatomic) NSString *status; /**< DNS answer's status */
@property(nonatomic) NSString *answer; /**< DNS Answers string representation */
@property(nonatomic) NSString *originalAnswer; /**< If blocked by CNAME, here will be DNS original answer's string representation */
@property(nonatomic) NSNumber *upstreamId; /**< ID of the upstream that provided this answer */
@property(nonatomic) NSInteger bytesSent; /**< Number of bytes sent to a server */
@property(nonatomic) NSInteger bytesReceived; /**< Number of bytes received from a server */
@property(nonatomic) NSArray<NSString *> *rules; /**< Filtering rules texts */
@property(nonatomic) NSArray<NSNumber *> *filterListIds; /**< Filter lists IDs of corresponding rules */
@property(nonatomic) BOOL whitelist; /**< True if filtering rule is whitelist */
@property(nonatomic) NSString *error; /**< If not empty, contains the error text (occurred while processing the DNS query) */
@property(nonatomic) BOOL cacheHit; /**< True if this response was served from the cache */
@property(nonatomic) BOOL dnssec; /**< True if this response has DNSSEC rrsig */
@property(nonatomic) NSInteger blockingReason; /**< DNS blocking reason (AGDnsBlockingReason) */

- (instancetype)initWithCoder:(NSCoder *)coder;

- (void)encodeWithCoder:(NSCoder *)coder;

- (NSString*)description;

@end

/**
 * @interface AGDnsProxyEvents
 * Set of DNS proxy events.
 */
@interface AGDnsProxyEvents : NSObject
/**
 * Raised right after a request is processed.
 * @note If there are several upstreams in proxy configuration, the proxy tries each one
 * consequently until it gets successful status, so in this case each failed upstream
 * fires the event - i.e., several events will be raised for the request.
 */
@property (nonatomic, copy) void (^onRequestProcessed)(const AGDnsRequestProcessedEvent *event);
@end
