#include <AGDnsProxy/AGDnsProxy.h>
#include <Foundation/Foundation.h>

#undef NDEBUG
#import <cassert>

int main() {

    // MARK: AGDnsUpstream description test

    auto *upstream = [[AGDnsUpstream alloc] initWithAddress:@"1.1.1.1"
                                                  bootstrap:@[@"2.2.2.2", @"3.3.3.3"]
                                                  timeoutMs:1000
                                                   serverIp:[@"192.168.0.1" dataUsingEncoding:NSUTF8StringEncoding]
                                                         id:42
                                      outboundInterfaceName:nil];
    {
        NSString *expected = [NSString stringWithFormat:
                              @"[(%p)AGDnsUpstream: address=1.1.1.1, bootstrap=(2.2.2.2, 3.3.3.3), timeoutMs=1000, serverIp=192.168.0.1, id=42]", upstream];
        assert([[upstream description] isEqualToString: expected]);
    }

    // MARK: AGDns64Settings description test

    auto *dns64Settings = [[AGDns64Settings alloc] initWithUpstreams:@[upstream]
                                                            maxTries:10
                                                          waitTimeMs:15];
    {
        NSString *expected = [NSString stringWithFormat:
                              @"[(%p)AGDns64Settings: waitTimeMs=15, upstreams=(\n"
                              "    \"[(%p)AGDnsUpstream: address=1.1.1.1, bootstrap=(2.2.2.2, 3.3.3.3), timeoutMs=1000, serverIp=192.168.0.1, id=42]\"\n"
                              ")]", dns64Settings, upstream];
        assert([[dns64Settings description] isEqualToString: expected]);
    }

    // MARK: AGListenerSettings description test

    auto *listenerSettings = [[AGListenerSettings alloc] initWithAddress:@"10.10.10.10"
                                                                    port:10
                                                                   proto:(AGListenerProtocol)1
                                                              persistent:YES
                                                           idleTimeoutMs:10];
    {
        NSString *expected = [NSString stringWithFormat:
                              @"[(%p)AGListenerSettings: address=10.10.10.10, port=10, proto=1]", listenerSettings];
        assert([[listenerSettings description] isEqualToString: expected]);
    }

    // MARK: AGOutboundProxyAuthInfo description test

    auto *outboundProxyAuthInfo = [[AGOutboundProxyAuthInfo alloc] initWithUsername: @"user"
                                                                           password: @"pass"];
    {
        NSString *expected = [NSString stringWithFormat:
                              @"[(%p)AGOutboundProxyAuthInfo: username=user]", outboundProxyAuthInfo];
        assert([[outboundProxyAuthInfo description] isEqualToString: expected]);
    }

    // MARK: AGOutboundProxySettings description test

    auto *outboundProxySettings = [[AGOutboundProxySettings alloc] initWithProtocol: (AGOutboundProxyProtocol)1
                                                                            address: @"192.168.0.1"
                                                                               port: 8080
                                                                           authInfo: outboundProxyAuthInfo
                                                                trustAnyCertificate: YES];
    {
        NSString *expected = [NSString stringWithFormat:
                              @"[(%p)AGOutboundProxySettings: protocol=1, address=192.168.0.1, port=8080, authInfo=[(%p)AGOutboundProxyAuthInfo: username=user], trustAnyCertificate=YES]",
                              outboundProxySettings, outboundProxyAuthInfo];
        assert([[outboundProxySettings description] isEqualToString: expected]);
    }

    // MARK: AGDnsFilterParams description test

    auto *dnsFilterParams = [[AGDnsFilterParams alloc] initWithId:35
                                                             data:@"Filter data"
                                                         inMemory:NO];
    {
        NSString *expected = [NSString stringWithFormat:
                              @"[(%p)AGDnsFilterParams: id=35]", dnsFilterParams];
        assert([[dnsFilterParams description] isEqualToString: expected]);
    }

    // MARK: AGDnsProxyConfig description test

    auto *dnsProxyConfig = [[AGDnsProxyConfig alloc] initWithUpstreams:@[upstream]
                                                             fallbacks:@[upstream]
                                                       fallbackDomains:@[@"adguard.com"]
                                                   detectSearchDomains:YES
                                                               filters:@[dnsFilterParams]
                                                blockedResponseTtlSecs:0
                                                         dns64Settings:dns64Settings
                                                             listeners:@[listenerSettings]
                                                         outboundProxy:outboundProxySettings
                                                         ipv6Available:NO
                                                             blockIpv6:NO
                                              adblockRulesBlockingMode:AGBM_REFUSED
                                                hostsRulesBlockingMode:AGBM_ADDRESS
                                                    customBlockingIpv4:@"8.8.8.8"
                                                    customBlockingIpv6:@"8.8.4.4"
                                                          dnsCacheSize:0
                                                       optimisticCache:YES
                                                        enableDNSSECOK:NO
                                          enableRetransmissionHandling:NO
                                                            helperPath:@"path/to/helper"];
    {
        NSString *expected = [NSString stringWithFormat:
                              @"[(%p)AGDnsProxyConfig:\n"
                              "ipv6Available=NO,\n"
                              "blockIpv6=NO,\n"
                              "adblockRulesBlockingMode=0,\n"
                              "hostsRulesBlockingMode=2,\n"
                              "customBlockingIpv4=8.8.8.8,\n"
                              "customBlockingIpv6=8.8.4.4,\n"
                              "enableDNSSECOK=NO,\n"
                              "enableRetransmissionHandling=NO,\n"
                              "detectSearchDomains=YES,\n"
                              "outboundProxy=[(%p)AGOutboundProxySettings: protocol=1, address=192.168.0.1, port=8080, authInfo=[(%p)AGOutboundProxyAuthInfo: username=user], trustAnyCertificate=YES],\n"
                              "upstreams=(\n"
                              "    \"[(%p)AGDnsUpstream: address=1.1.1.1, bootstrap=(2.2.2.2, 3.3.3.3), timeoutMs=1000, serverIp=192.168.0.1, id=42]\"\n"
                              "),\n"
                              "fallbacks=(\n"
                              "    \"[(%p)AGDnsUpstream: address=1.1.1.1, bootstrap=(2.2.2.2, 3.3.3.3), timeoutMs=1000, serverIp=192.168.0.1, id=42]\"\n"
                              "),\n"
                              "fallbackDomains=(\n"
                              "    \"adguard.com\"\n"
                              "),\n"
                              "filters=(\n"
                              "    \"[(%p)AGDnsFilterParams: id=35]\"\n"
                              "),\n"
                              "dns64Settings=[(%p)AGDns64Settings: waitTimeMs=15, upstreams=(\n"
                              "    \"[(%p)AGDnsUpstream: address=1.1.1.1, bootstrap=(2.2.2.2, 3.3.3.3), timeoutMs=1000, serverIp=192.168.0.1, id=42]\"\n"
                              ")],\n"
                              "listeners=(\n"
                              "    \"[(%p)AGListenerSettings: address=10.10.10.10, port=10, proto=1]\"\n"
                              ")]",
                              dnsProxyConfig, outboundProxySettings, outboundProxyAuthInfo, upstream, upstream, dnsFilterParams, dns64Settings, upstream, listenerSettings];
        assert([[dnsProxyConfig description] isEqualToString: expected]);
    }
}
