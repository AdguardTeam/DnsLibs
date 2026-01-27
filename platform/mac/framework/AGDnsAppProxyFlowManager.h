#pragma once

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import "AGDnsProxy.h"

typedef NS_ENUM(NSInteger, AGDnsAppProxyFlowMode) {
    /** Redirect - request is redirected to DnsProxy. */
    AGDnsAppProxyFlowModeRedirect = 0,
    /** Filter - request/reply are transparently filtered by DnsProxy. */
    AGDnsAppProxyFlowModeFilter = 1,
    /** Bypass - DNS requests are bypassed. */
    AGDnsAppProxyFlowModeBypass = 2,
};

/**
 * @brief A helper that manages per-flow handlers for NetworkExtension App Proxy flows.
 *
 * `AGDnsAppProxyFlowManager` accepts `NEAppProxyFlow` objects (TCP/UDP) and either:
 * - forwards DNS messages to `AGDnsProxy`, or
 * - bypasses the proxy and transparently forwards traffic to the original destination
 *   when `bypass` is enabled.
 *
 * The typical usage is from an `NEAppProxyProvider`/`NEDNSProxyProvider` implementation.
 * The snippet below mirrors `DNSProxyProvider.swift` from `DnsLibsTestApp`.
 *
 * @code{.swift}
 * class DNSProxyProvider: NEDNSProxyProvider {
 *     var dnsProxy: AGDnsProxy?
 *     var dnsFlowManager: AGDnsAppProxyFlowManager?
 *
 *     func startDnsProxy() throws {
 *         // ... configure AGDnsProxy ...
 *         dnsProxy = AGDnsProxy(config: config, handler: events, error: &error)
 *         dnsFlowManager = AGDnsAppProxyFlowManager(dnsProxy: dnsProxy)
 *     }
 *
 *     override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
 *         return dnsFlowManager?.handle(flow, mode: .redirect) ?? false
 *     }
 *
 *     override func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow,
 *                                    initialRemoteEndpoint remoteEndpoint: NWEndpoint) -> Bool {
 *         return dnsFlowManager?.handle(flow, mode: .redirect) ?? false
 *     }
 * }
 * @endcode
 */

@interface AGDnsAppProxyFlowManager : NSObject

- (instancetype)init NS_UNAVAILABLE;

/**
 * @brief Create a flow manager.
 * @param dnsProxy The DNS proxy instance used when `bypass` is disabled.
 */
- (instancetype)initWithDnsProxy:(AGDnsProxy *)dnsProxy NS_DESIGNATED_INITIALIZER;

/**
 * @brief Handle a newly accepted app proxy flow.
 *
 * If `mode` is `AGDnsAppProxyFlowModeBypass`, the flow is forwarded without using `AGDnsProxy`.
 * Otherwise, DNS messages are passed to `AGDnsProxy` and replies are written back
 * to the originating flow.
 *
 * @param flow A TCP or UDP app proxy flow.
 * @param mode Flow processing mode.
 * @return `YES` if the flow type is supported and a handler was created.
 */
- (BOOL)handleAppProxyFlow:(NEAppProxyFlow *)flow mode:(AGDnsAppProxyFlowMode)mode;

/**
 * @brief Stop all active flow handlers and release resources.
 */
- (void)stop;

@end