#include <AGDnsProxy/AGDnsProxy.h>
#include <Foundation/Foundation.h>

/// Test that we don't crash when `[AGDnsProxy initWithConfig]` fails because listeners couldn't be initialized
static int regressTestListenerFailsInit() {
    // This listener MUST cause initialization to fail
    auto *listener = [[AGListenerSettings alloc] init];
    listener.address = @"asdf";
    listener.port = 0;
    listener.proto = AGLP_UDP;
    listener.persistent = NO;
    listener.idleTimeoutMs = 10;

    auto *upstream = [[AGDnsUpstream alloc] init];
    upstream.address = @"1.1.1.1";
    upstream.bootstrap = nil;
    upstream.timeoutMs = 1000;
    upstream.serverIp = nil;
    upstream.id = 42;
    upstream.outboundInterfaceName = nil;

    auto *config = [[AGDnsProxyConfig alloc] init];
    config.upstreams = @[upstream];
    config.fallbacks = @[];
    config.fallbackDomains = @[];
    config.detectSearchDomains = YES;
    config.filters = @[];
    config.blockedResponseTtlSecs = 0;
    config.dns64Settings = nil;
    config.listeners = @[listener];
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
    if (!error || proxy) {
        [proxy stop];
        return 1;
    }
    return 0;
}

int main() {
    return regressTestListenerFailsInit();
}
