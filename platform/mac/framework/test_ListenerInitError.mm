#include <AGDnsProxy/AGDnsProxy.h>
#include <Foundation/Foundation.h>

int main() {
    auto *good_listener = [[AGListenerSettings alloc] init];
    good_listener.address = @"::";
    good_listener.port = 53;
    good_listener.proto = AGLP_UDP;
    good_listener.persistent = NO;
    good_listener.idleTimeoutMs = 0;
    
    auto *bad_listener = [[AGListenerSettings alloc] init];
    bad_listener.address = @"127.0.0.1";
    bad_listener.port = 53;
    bad_listener.proto = AGLP_TCP;
    bad_listener.persistent = NO;
    bad_listener.idleTimeoutMs = 10000;
    
    auto *listeners = @[good_listener, bad_listener];
    
    auto *upstream = [[AGDnsUpstream alloc] init];
    upstream.address = @"94.140.14.14";
    upstream.bootstrap = nil;
    upstream.timeoutMs = 1000;
    upstream.serverIp = nil;
    upstream.id = 42;
    upstream.outboundInterfaceName = nil;

    auto *config = [[AGDnsProxyConfig alloc] init];
    config.upstreams = @[upstream];
    config.fallbacks = @[];
    config.fallbackDomains = @[];
    config.detectSearchDomains = NO;
    config.filters = @[];
    config.blockedResponseTtlSecs = 0;
    config.dns64Settings = nil;
    config.listeners = listeners;
    config.outboundProxy = nil;
    config.ipv6Available = NO;
    config.blockIpv6 = NO;
    config.adblockRulesBlockingMode = AGBM_REFUSED;
    config.hostsRulesBlockingMode = AGBM_ADDRESS;
    config.customBlockingIpv4 = nil;
    config.customBlockingIpv6 = nil;
    config.dnsCacheSize = 0;
    config.optimisticCache = YES;
    config.enableDNSSECOK = NO;
    config.enableRetransmissionHandling = NO;
    config.enableRouteResolver = NO;
    config.blockEch = NO;
    config.helperPath = nil;

    auto *handler = [AGDnsProxyEvents new];
    NSError *error;
    auto *proxy = [[AGDnsProxy alloc] initWithConfig:config handler:handler error:&error];
    if (proxy || !error || error.code != AGDPE_PROXY_INIT_LISTENER_ERROR) {
        [proxy stop];
        return 1;
    }
    return 0;
}
