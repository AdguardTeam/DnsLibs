#import <Foundation/Foundation.h>

#import "AGDnsProxy.h"

/**
 * The protocol for the DNS proxy event handler.
 * The implementation of this protocol sits on the client side.
 */
@protocol AGDnsProxyEventsXPC

/** Invoked after a DNS request is processed. */
- (void)onRequestProcessed:(const AGDnsRequestProcessedEvent *)event;

@end

/**
 * The protocol for communicating with the DNS proxy over XPC.
 * The implementation of this protocol sits on the service side.
 * An implementation is provided in `AGDnsProxyXPCImpl` below.
 */
@protocol AGDnsProxyXPC

/**
 * Reconfig the DNS proxy.
 * @param config Configuration.
 * @param handler Invoked with `nil` after the proxy has started, or with the error otherwise.
 */
- (void)reconfig:(AGDnsProxyConfig *)config
     completionHandler:(void (^)(NSError *))handler NS_SWIFT_NOTHROW;

/**
 * Process an IP datagram, carrying a UDP payload, carrying a DNS request.
 * @param packet The datagram to process.
 * @param completionHandler Invoked with an IP datagram, carrying a UDP payload, carrying the DNS response.
 */
- (void)handlePacket:(NSData *)packet completionHandler:(void (^)(NSData *))completionHandler;

/**
 * Stop the DNS proxy.
 * @param handler Invoked after the proxy has stopped.
 */
- (void)stopWithCompletionHandler:(void (^)(void))handler;

@end

@interface AGDnsProxyXPCImpl : NSObject <AGDnsProxyXPC>

- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithConfig:(AGDnsProxyConfig *)config
                        events:(id<AGDnsProxyEventsXPC>)events
                         error:(NSError **)error;

- (AGDnsProxy *)unwrap;

/** Return an `NSXPCInterface` that describes the `AGDnsProxyXPC` protocol. */
+ (NSXPCInterface *)xpcInterface;

@end
