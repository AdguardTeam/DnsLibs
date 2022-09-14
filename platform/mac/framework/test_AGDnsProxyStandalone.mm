#include <AGDnsProxy/AGDnsProxy.h>
#include <Foundation/Foundation.h>

int main() {
    [AGLogger setLevel:AGLL_TRACE];
    auto *listener = [[AGListenerSettings alloc] initWithAddress:@"::"
                                                            port:53
                                                           proto:AGLP_UDP
                                                      persistent:NO
                                                   idleTimeoutMs:10];
    auto *upstream = [[AGDnsUpstream alloc] initWithAddress:@"tls://94.140.14.14"
                                                  bootstrap:@[@"1.1.1.1"]
                                                  timeoutMs:1000
                                                   serverIp:nil
                                                         id:42
                                      outboundInterfaceName:nil];
    auto *fallback = [[AGDnsUpstream alloc] initWithAddress:@"1.1.1.1"
                                                  bootstrap:nil
                                                  timeoutMs:1000
                                                   serverIp:nil
                                                         id:43
                                      outboundInterfaceName:nil];
    auto *config = [[AGDnsProxyConfig alloc] initWithUpstreams:@[upstream]
                                                     fallbacks:@[fallback]
                                               fallbackDomains:@[]
                                           detectSearchDomains:YES
                                                       filters:@[]
                                        blockedResponseTtlSecs:0
                                                 dns64Settings:nil
                                                     listeners:@[listener]
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
                                           enableRouteResolver:NO
                                                      blockEch:NO
                                                    helperPath:nil];

    auto *handler = [AGDnsProxyEvents new];
    NSError *error;
    auto *proxy = [[AGDnsProxy alloc] initWithConfig:config handler:handler error:&error];
    if (error || !proxy) {
        NSLog(@"%@", error);
        [proxy stop];
        return 1;
    }
    while (getchar() != 's') {
        ;
    }
    return 0;
}
