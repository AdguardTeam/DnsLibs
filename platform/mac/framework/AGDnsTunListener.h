#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * Completion handler for DNS message processing.
 * 
 * This handler may be called asynchronously on any thread.
 * The implementation must copy the reply data if it needs to be used after the handler returns.
 * 
 * @param reply DNS response message, or nil if no response should be sent
 */
typedef void (^AGDnsTunListenerReplyHandler)(NSData * _Nullable reply);

/**
 * Handler for incoming DNS messages from TUN interface.
 * 
 * This handler is called for both UDP and TCP DNS traffic.
 * The handler may process the message asynchronously and call replyHandler at any time,
 * on any thread. The message data is copied and remains valid after the handler returns.
 * 
 * @param message DNS message (query) without transport headers
 * @param replyHandler Completion handler to send the response back. May be called asynchronously.
 */
typedef void (^AGDnsTunListenerMessageHandler)(NSData *message, AGDnsTunListenerReplyHandler replyHandler);


/**
 * TUN listener that handles both UDP and TCP DNS traffic from a TUN device.
 * 
 * This class wraps the C++ TunListener and provides an Objective-C interface
 * for processing DNS queries from a TUN/TAP network interface.
 *
 * Example usage (iOS VPN extension with NEPacketTunnelFlow):
 * @code
 * AGDnsTunListener *listener = [[AGDnsTunListener alloc]
 *     initWithTunFd:nil
 *      orTunnelFlow:self.packetFlow
 *               mtu:1500
 *    messageHandler:^(NSData *request, AGDnsTunListenerReplyHandler replyHandler) {
 *        // Process request asynchronously and call replyHandler when done
 *        [dnsProxy handleMessage:request
 *                       withInfo:nil
 *          withCompletionHandler:replyHandler];
 *    }
 *             error:&error];
 * // Packets are read/written automatically via tunnelFlow
 * @endcode
 *
 * Example usage (autonomous mode with TUN fd):
 * @code
 * AGDnsTunListener *listener = [[AGDnsTunListener alloc]
 *     initWithTunFd:@(tunFd)
 *      orTunnelFlow:nil
 *               mtu:1500
 *    messageHandler:^(NSData *request, AGDnsTunListenerReplyHandler replyHandler) {
 *        // Process request asynchronously and call replyHandler when done
 *        [dnsProxy handleMessage:request
 *                       withInfo:nil
 *          withCompletionHandler:replyHandler];
 *    }
 *             error:&error];
 * // Listener manages TUN device internally
 * @endcode
 */
@interface AGDnsTunListener : NSObject

/**
 * Initialize TUN listener.
 * 
 * Two modes are supported:
 * 1. Autonomous mode (fd >= 0, tunnelFlow == nil): Listener manages TUN device internally
 * 2. NEPacketTunnelFlow mode (fd == nil, tunnelFlow != nil): For iOS VPN extensions
 *
 * @param fd TUN device file descriptor (NSNumber with int value, or nil for NEPacketTunnelFlow mode)
 * @param tunnelFlow NEPacketTunnelFlow for iOS VPN extensions (mutually exclusive with fd)
 * @param mtu Maximum Transmission Unit size (use 0 for default 1500)
 * @param handler Message handler for processing DNS queries
 * @param error Error output parameter (will be set if initialization fails)
 * @return Initialized instance or nil on error
 */
- (nullable instancetype)initWithTunFd:(nullable NSNumber *)fd
                          orTunnelFlow:(nullable NEPacketTunnelFlow *)tunnelFlow
                                   mtu:(int)mtu
                        messageHandler:(AGDnsTunListenerMessageHandler)handler
                                 error:(NSError **)error;

/**
 * Stop the listener and clean up resources.
 * 
 * This method stops the internal event loop and releases all resources.
 * After calling this method, the listener cannot be reused.
 */
- (void)stop;

@end

NS_ASSUME_NONNULL_END
