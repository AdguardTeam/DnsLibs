#import "vpn.h"
#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>


@implementation AGVpn {
    NETunnelProviderManager *mgr;
}


// Create new VPN configuration and start it.
// Remove VPN configuration with the same name, if it already exists.
- (void) load
{
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler
        :^(NSArray<NETunnelProviderManager *> * _Nullable managers, NSError * _Nullable e)
    {
        if (e != nil) {
            NSLog(@"load err: %@", e);
            return;
        }

        for (NETunnelProviderManager *m in managers) {
            if ([m.localizedDescription isEqual: @"Adguard VPN"]) {
                [m removeFromPreferencesWithCompletionHandler: ^(NSError * _Nullable error) {
                    return;
                }];
            }
        }

        NETunnelProviderProtocol *p = [[NETunnelProviderProtocol alloc] init];
        p.providerBundleIdentifier = @"com.adguard.dnsproxy2.ext";
        p.serverAddress = @"127.0.0.1";

        NETunnelProviderManager *m = [[NETunnelProviderManager alloc] init];
        m.localizedDescription = @"Adguard VPN";
        m.protocolConfiguration = p;
        m.enabled = true;
        NSLog(@"VPN status: %li", (long)m.connection.status);

        [m saveToPreferencesWithCompletionHandler: ^(NSError *e) {
            if (e != nil) {
                NSLog(@"Save Error: %@", e.description);
                return;
            }

            NSLog(@"Created");

            [m loadFromPreferencesWithCompletionHandler: ^(NSError * _Nullable e) {
                if (e != nil) {
                    NSLog(@"Load Error: %@", e.description);
                    return;
                }

                self->mgr = m;
                [self start];
            }];
        }];
    }];
}

// Start proxy server and start VPN
- (void) start
{
    NSLog(@"Starting %@ status:%li"
        , self->mgr.localizedDescription , (long)self->mgr.connection.status);

    NEVPNConnection *con = self->mgr.connection;
    NSMutableDictionary<NSString *,NSObject *> *options = [[NSMutableDictionary alloc] init];
    NSError *error;
    if (![con startVPNTunnelWithOptions: options andReturnError: &error]
            || error != nil) {
        NSLog(@"startVPNTunnelWithOptions tunnel start error: %@", error.description);
        return;
    }

    NSLog(@"Started.  status:%li", (long)con.status);
}

- (void) close
{
    if (self->mgr != NULL) {
        [self->mgr.connection stopVPNTunnel];
        [mgr removeFromPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
            return;
        }];
    }
}

@end


static AGVpn *vpn;

void AGVpnStart(void)
{
    vpn = [[AGVpn alloc] init];
    [vpn load];
    [vpn start];
}

void AGVpnClose(void)
{
    [vpn close];
}
