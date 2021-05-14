#include <AGDnsProxy/AGDnsProxy.h>
#include <Foundation/Foundation.h>

/// Test that we don't crash when `[AGDnsProxy initWithConfig]` fails because listeners couldn't be initialized
static int regressTestListenerFailsInit() {
    // This listener MUST cause initialization to fail
    auto *listener = [[AGListenerSettings alloc] initWithAddress:@"asdf"
                                                            port:0
                                                           proto:AGLP_UDP
                                                      persistent:NO
                                                   idleTimeoutMs:10];
    auto *upstream = [[AGDnsUpstream alloc] initWithAddress:@"1.1.1.1"
                                                  bootstrap:nil
                                                  timeoutMs:1000
                                                   serverIp:nil
                                                         id:42
                                      outboundInterfaceName:nil];
    auto *config = [[AGDnsProxyConfig alloc] initWithUpstreams:@[upstream]
                                                     fallbacks:@[]
                                             handleDNSSuffixes:NO
                                               userDNSSuffixes:@[]
                                                       filters:@[]
                                        blockedResponseTtlSecs:0
                                                 dns64Settings:nil
                                                     listeners:@[listener]
                                                 ipv6Available:NO
                                                     blockIpv6:NO
                                                  blockingMode:AGBM_DEFAULT
                                            customBlockingIpv4:nil
                                            customBlockingIpv6:nil
                                                  dnsCacheSize:0
                                               optimisticCache:YES
                                                enableDNSSECOK:NO
                                                    helperPath:nil];

    auto *handler = [AGDnsProxyEvents new];
    NSError *error;
    auto *proxy = [[AGDnsProxy alloc] initWithConfig:config handler:handler error:&error];
    if (!error || proxy) {
        return 1;
    }
    return 0;
}

int main() {
    return regressTestListenerFailsInit();
}
