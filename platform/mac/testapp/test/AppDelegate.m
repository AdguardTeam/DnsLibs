#import "AppDelegate.h"
#include "vpn.h"

@interface AppDelegate ()

@end

@implementation AppDelegate {
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    // Insert code here to initialize your application
    AGVpnStart();
}

- (void)applicationWillTerminate:(NSNotification *)aNotification {
    // Insert code here to tear down your application
    AGVpnClose();
}

@end
