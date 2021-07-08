#include <AGDnsProxy/AGDnsProxy.h>
#include <Foundation/Foundation.h>

/// Test that listeners bind to localhost@53 for TCP/UDP and IPv4/IPv6
int main() {
    auto *listeners = @[
            // Good
            [[AGListenerSettings alloc] initWithAddress:@"::" port:53 proto:AGLP_UDP
                                             persistent:NO idleTimeoutMs:0],
            // Bad
            [[AGListenerSettings alloc] initWithAddress:@"127.0.0.1" port:53 proto:AGLP_TCP
                                             persistent:NO idleTimeoutMs:10000]];
    auto *upstream = [[AGDnsUpstream alloc] initWithAddress:@"94.140.14.14"
                                                  bootstrap:nil
                                                  timeoutMs:1000
                                                   serverIp:nil
                                                         id:42
                                      outboundInterfaceName:nil];
    auto *config = [[AGDnsProxyConfig alloc] initWithUpstreams:@[upstream]
                                                     fallbacks:@[]
                                               fallbackDomains:@[]
                                           detectSearchDomains:NO
                                                       filters:@[]
                                        blockedResponseTtlSecs:0
                                                 dns64Settings:nil
                                                     listeners:listeners
                                                 outboundProxy:nil
                                                 ipv6Available:NO
                                                     blockIpv6:NO
                                      adblockRulesBlockingMode:AGBM_REFUSED
                                        hostsRulesBlockingMode:AGBM_ADDRESS
                                            customBlockingIpv4:nil
                                            customBlockingIpv6:nil
                                                  dnsCacheSize:0
                                               optimisticCache:YES
                                                enableDNSSECOK:NO
                                  enableRetransmissionHandling:NO
                                                    helperPath:nil];

    auto *handler = [AGDnsProxyEvents new];
    NSError *error;
    auto *proxy = [[AGDnsProxy alloc] initWithConfig:config handler:handler error:&error];
    if (proxy || !error || error.code != AGDPE_PROXY_INIT_LISTENER_ERROR) {
        return 1;
    }
    return 0;
}
