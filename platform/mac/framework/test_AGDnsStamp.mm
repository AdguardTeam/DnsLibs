#import <AGDnsProxy/AGDnsProxy.h>

#undef NDEBUG
#import <cassert>

int main() {
    NSError *error = nil;
    auto *stamp = [AGDnsStamp stampWithString:@"asdfasdfasdfsdf" error:&error];
    assert(!stamp);
    assert(error);

    error = nil;
    auto *doh_str =
            @"sdns://AgMAAAAAAAAADDk0LjE0MC4xNC4xNKDK_rq-yv66vsr-ur7K_rq-yv66vsr-ur7K_rq-yv66viDerb7v3q2-796tvu_"
             "erb7v3q2-796tvu_erb7v3q2-7w9kbnMuYWRndWFyZC5jb20KL2Rucy1xdWVyeQ";
    stamp = [AGDnsStamp stampWithString:doh_str error:&error];
    assert(stamp);
    assert(!error);
    assert([stamp.providerName isEqualToString:@"dns.adguard.com"]);
    assert([stamp.path isEqualToString:@"/dns-query"]);
    auto props = [stamp.properties unsignedLongLongValue];
    assert(props & AGSIP_DNSSEC);
    assert(props & AGSIP_NO_LOG);
    assert(!(props & AGSIP_NO_FILTER));
    assert(stamp.hashes);
    assert(stamp.hashes.count == 2);
    assert([stamp.prettyUrl isEqualToString:@"https://dns.adguard.com/dns-query"]);
    assert([stamp.prettierUrl isEqualToString:@"https://dns.adguard.com/dns-query"]);
    assert([stamp.stringValue isEqualToString:doh_str]);

    stamp.proto = AGSPT_DOQ;
    stamp.hashes = @[[NSData dataWithBytes:"\xca\xfe\xba\xbe" length:4]];
    stamp.properties = @(AGSIP_NO_FILTER);
    stamp.path = nil;

    assert([stamp.prettyUrl isEqualToString:@"quic://dns.adguard.com"]);
    assert([stamp.prettierUrl isEqualToString:@"quic://dns.adguard.com"]);
    assert([stamp.stringValue isEqualToString:@"sdns://BAQAAAAAAAAADDk0LjE0MC4xNC4xNATK_rq-D2Rucy5hZGd1YXJkLmNvbQ"]);

    stamp.proto = AGSPT_DNSCRYPT;
    stamp.hashes = nil;
    stamp.providerName = @"2.dnscrypt-cert.adguard";
    stamp.serverPublicKey = [NSData dataWithBytes:"\xca\xfe\xba\xbe\xde\xad\xbe\xef" length:8];

    assert([stamp.prettyUrl isEqualToString:@"sdns://AQQAAAAAAAAADDk0LjE0MC4xNC4xNAjK_rq-3q2-7xcyLmRuc2NyeXB0LWNlcnQuYWRndWFyZA"]);
    assert([stamp.prettierUrl isEqualToString:@"dnscrypt://2.dnscrypt-cert.adguard"]);
    assert([stamp.stringValue isEqualToString:@"sdns://AQQAAAAAAAAADDk0LjE0MC4xNC4xNAjK_rq-3q2-7xcyLmRuc2NyeXB0LWNlcnQuYWRndWFyZA"]);

    stamp = [AGDnsStamp stampWithString:@"sdns://AQcAAAAAAAAAI2RvdHRsczovLzIzYTdkYWIxLmQuYWRndWFyZC1kbnMuY29tABAyLmRuc2NyeXB0LWNlcnQu" error:&error];
    assert(!stamp);
    assert(error);

    stamp = [AGDnsStamp stampWithString:@"sdns://AQcAAAAAAAAAI2RvdHRsczovLzIzYTdkYWIxLmQuYWRndWFyZC1kbnMuY29tABAyLmRuc2NyeXB0LWNlcnQu" error:nil];
    assert(!stamp);

    return 0;
}
