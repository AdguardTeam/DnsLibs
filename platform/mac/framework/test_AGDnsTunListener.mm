/**
 * @file test_AGDnsTunListener.mm
 * @brief Usage example for AGDnsTunListener
 * 
 * This example demonstrates AGDnsTunListener in different modes.
 * 
 * MODES SUPPORTED BY AGDnsTunListener:
 * 1. Autonomous mode (default): fd=@(tunFd), tunnelFlow=nil
 *    - Listener manages TUN device internally
 *    - Uses tcpip library for packet processing
 * 
 * 2. External mode (--external): fd=nil, tunnelFlow=packetFlow
 *    - Simulates iOS VPN extension behavior
 *    - Uses NEPacketTunnelFlow for packet reading/writing
 * 
 * REQUIREMENTS:
 * - Root privileges (sudo) to create TUN device
 * - macOS operating system
 * 
 * HOW TO RUN:
 *   # Autonomous mode (default):
 *   sudo ./test_AGDnsTunListener
 *   
 *   # External mode (with NEPacketTunnelFlow):
 *   sudo ./test_AGDnsTunListener --external
 * 
 * TESTING:
 *   dig example.com @198.18.53.53
 *   dig example.com +tcp @198.18.53.53
 *   dig evil.com @198.18.53.53  (should be blocked)
 *   dig evil.org @198.18.53.53  (should be blocked)
 */

#import <AGDnsProxy/AGDnsProxy.h>
#import <AGDnsProxy/AGDnsTunListener.h>
#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <atomic>
#include <thread>

/**
 * Mock NEPacketTunnelFlow for testing external mode
 * Reads from TUN fd and simulates NEPacketTunnelFlow behavior
 */
@interface MockPacketTunnelFlow : NEPacketTunnelFlow

- (instancetype)initWithTunFd:(int)fd;
- (void)readPacketsWithCompletionHandler:(void (^)(NSArray<NSData *> *, NSArray<NSNumber *> *))completionHandler;
- (void)writePackets:(NSArray<NSData *> *)packets withProtocols:(NSArray<NSNumber *> *)protocols;
@end

@implementation MockPacketTunnelFlow {
    int _tunFd;
}

- (instancetype)initWithTunFd:(int)fd {
    self = [super init];
    if (self) {
        _tunFd = fd;
    }
    return self;
}

- (void)readPacketsWithCompletionHandler:(void (^)(NSArray<NSData *> *, NSArray<NSNumber *> *))completionHandler {
    // Mimic real NEPacketTunnelFlow behavior:
    // - Read 1-N packets from TUN (blocking until at least 1 packet arrives)
    // - Call completionHandler ONCE with all packets
    // - Operation completes (caller must call readPackets again for next batch)

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSMutableArray<NSData *> *packets = [NSMutableArray array];
        NSMutableArray<NSNumber *> *protocols = [NSMutableArray array];
        
        // Read up to 32 packets (typical batch size for NEPacketTunnelFlow)
        const int MAX_PACKETS = 32;
        uint8_t buffer[4096];
        
        // Wait for first packet using poll()
        struct pollfd pfd = {.fd = _tunFd, .events = POLLIN};
        int poll_ret = poll(&pfd, 1, -1); // Block until packet arrives
        
        if (poll_ret <= 0) {
            // Error - stop reading
            return;
        }
        
        // Read first packet
        ssize_t nread = read(_tunFd, buffer, sizeof(buffer));
        
        if (nread > 0) {
            // On macOS, utun packets have 4-byte header (protocol family)
            constexpr size_t UTUN_HDR_SIZE = 4;
            if ((size_t)nread >= UTUN_HDR_SIZE) {
                // Read protocol family from header
                uint32_t family_be;
                memcpy(&family_be, buffer, sizeof(family_be));
                int family = ntohl(family_be);
                
                // Create NSData without utun header
                NSData *packet = [NSData dataWithBytes:buffer + UTUN_HDR_SIZE
                                                length:nread - UTUN_HDR_SIZE];
                [packets addObject:packet];
                [protocols addObject:@(family)];
            }
            
            // Try to read more packets (non-blocking)
            for (int i = 1; i < MAX_PACKETS; i++) {
                nread = read(_tunFd, buffer, sizeof(buffer));
                
                if (nread < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // No more packets available right now
                        break;
                    }
                    // Read error - stop
                    break;
                }
                
                if (nread > 0 && (size_t)nread >= UTUN_HDR_SIZE) {
                    uint32_t family_be;
                    memcpy(&family_be, buffer, sizeof(family_be));
                    int family = ntohl(family_be);
                    
                    NSData *packet = [NSData dataWithBytes:buffer + UTUN_HDR_SIZE
                                                    length:nread - UTUN_HDR_SIZE];
                    [packets addObject:packet];
                    [protocols addObject:@(family)];
                }
            }
        }
        
        // Call completion handler ONCE with all collected packets
        if (packets.count > 0) {
            completionHandler(packets, protocols);
        }
    });
}

- (void)writePackets:(NSArray<NSData *> *)packets withProtocols:(NSArray<NSNumber *> *)protocols {
    for (size_t i = 0; i < packets.count; ++i) {
        NSData *packet = packets[i];
        NSNumber *protocol = protocols[i];
        
        // Add utun header (4 bytes: protocol family in network byte order)
        uint32_t family_be = htonl(protocol.intValue);
        
        // Allocate buffer for header + packet
        size_t total_size = 4 + packet.length;
        uint8_t *buffer = (uint8_t *)malloc(total_size);
        memcpy(buffer, &family_be, 4);
        memcpy(buffer + 4, packet.bytes, packet.length);
        
        write(_tunFd, buffer, total_size);
        free(buffer);
    }
}

- (void)dealloc {
    // Nothing to clean up - no background threads
}

@end

/**
 * Create a TUN device on macOS
 * @param remote_addr Output parameter for the remote address to use for testing
 * @return File descriptor or -1 on error
 */
static int create_tun_device(NSString **remote_addr) {
    // Create utun device
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        NSLog(@"Failed to create socket: %s", strerror(errno));
        return -1;
    }

    struct ctl_info info = {};
    strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
    
    if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
        NSLog(@"Failed to get utun control info: %s", strerror(errno));
        close(fd);
        return -1;
    }

    struct sockaddr_ctl addr = {};
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0; // 0 means kernel will assign next available unit

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        NSLog(@"Failed to connect to utun control: %s", strerror(errno));
        close(fd);
        return -1;
    }

    // Get the interface name
    char ifname_buf[IFNAMSIZ];
    socklen_t ifname_len = sizeof(ifname_buf);
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname_buf, &ifname_len) < 0) {
        NSLog(@"Failed to get utun interface name: %s", strerror(errno));
        close(fd);
        return -1;
    }

    NSString *ifname = [NSString stringWithUTF8String:ifname_buf];
    NSLog(@"Created TUN device: %@", ifname);

    // Configure the interface
    NSString *local_addr_str = @"198.18.53.1";
    NSString *remote_addr_str = @"198.18.53.53";
    NSString *netmask = @"255.255.255.252";

    NSString *cmd = [NSString stringWithFormat:
        @"ifconfig %@ %@ %@ netmask %@ up",
        ifname, local_addr_str, remote_addr_str, netmask];
    
    NSLog(@"Configuring interface: %@", cmd);
    int ret = system(cmd.UTF8String);
    if (ret != 0) {
        NSLog(@"Failed to configure interface (exit code: %d)", ret);
        close(fd);
        return -1;
    }

    // Add route for DNS server
    cmd = [NSString stringWithFormat:@"route add -host %@ -interface %@", remote_addr_str, ifname];
    NSLog(@"Adding route: %@", cmd);
    ret = system(cmd.UTF8String);
    if (ret != 0) {
        NSLog(@"Warning: Failed to add route (exit code: %d)", ret);
        // Continue anyway
    }

    // Set non-blocking mode for TUN fd
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        NSLog(@"Warning: Failed to set non-blocking mode: %s", strerror(errno));
    }

    *remote_addr = remote_addr_str;
    return fd;
}

int main(int argc, const char *argv[]) {
    [AGDnsLogger setLevel:AGDLLTrace];

    // Parse arguments
    bool external_mode = false;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--external") == 0 || strcmp(argv[i], "-e") == 0) {
            external_mode = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            NSLog(@"Usage: %s [--external|-e]", argv[0]);
            NSLog(@"  --external, -e  Use external mode (with NEPacketTunnelFlow)");
            return 0;
        }
    }

    NSLog(@"Starting in %@ mode", external_mode ? @"EXTERNAL" : @"AUTONOMOUS");

    // Create TUN device
    NSString *remote_addr = nil;
    int tun_fd = create_tun_device(&remote_addr);
    if (tun_fd < 0) {
        NSLog(@"Failed to create TUN device");
        return 1;
    }
    NSLog(@"TUN device created successfully (fd=%d)", tun_fd);

    // Configure DnsProxy
    AGDnsProxyConfig *config = [AGDnsProxyConfig getDefault];
    
    // Upstream
    auto *upstream = [[AGDnsUpstream alloc] init];
    upstream.address = @"tls://dns.adguard-dns.com";
    upstream.bootstrap = @[@"1.1.1.1"];
    upstream.serverIp = nil;
    upstream.id = 42;
    upstream.outboundInterfaceName = nil;
    upstream.fingerprints = @[@"pUZw/ajtE73tCpUV810KK+2TfhAKpignA8s7hyggVew="]; // dns.adguard-dns.com public key fingerprint

    // Fallback
    auto *fallback = [[AGDnsUpstream alloc] init];
    fallback.address = @"1.1.1.1";
    fallback.bootstrap = nil;
    fallback.serverIp = nil;
    fallback.id = 43;
    fallback.outboundInterfaceName = nil;

    // Filters for testing
    auto *hostsFilter = [[AGDnsFilterParams alloc] init];
    hostsFilter.id = 1;
    hostsFilter.data = @"0.0.0.0 evil.com\n";
    hostsFilter.inMemory = YES;

    auto *adblockFilter = [[AGDnsFilterParams alloc] init];
    adblockFilter.id = 2;
    adblockFilter.data = @"||evil.org^\n";
    adblockFilter.inMemory = YES;

    config.upstreams = @[upstream];
    config.fallbacks = @[fallback];
    config.filters = @[hostsFilter, adblockFilter];
    config.upstreamTimeoutMs = 1000;

    // Events handler
    auto *events = [[AGDnsProxyEvents alloc] init];

    // Initialize DnsProxy
    NSError *error = nil;
    auto *proxy = [[AGDnsProxy alloc] initWithConfig:config handler:events error:&error];
    if (error || !proxy) {
        NSLog(@"%@", error);
        close(tun_fd);
        return 1;
    }

    // Initialize TunListener
    MockPacketTunnelFlow *mockFlow = nil;
    AGDnsTunListener *tunListener = nil;
    
    if (external_mode) {
        // External mode: use MockPacketTunnelFlow
        mockFlow = [[MockPacketTunnelFlow alloc] initWithTunFd:tun_fd];
        
        tunListener = [[AGDnsTunListener alloc]
            initWithTunFd:nil           // No TUN fd in external mode
             orTunnelFlow:mockFlow      // Use NEPacketTunnelFlow
                      mtu:0             // Use default MTU
           messageHandler:^(NSData *request, AGDnsTunListenerReplyHandler replyHandler) {
               // Process DNS request through DnsProxy
               [proxy handleMessage:request
                           withInfo:nil
              withCompletionHandler:replyHandler];
           }
                    error:&error];
    } else {
        // Autonomous mode: TunListener manages TUN fd
        tunListener = [[AGDnsTunListener alloc]
            initWithTunFd:@(tun_fd)     // Autonomous mode with TUN fd
             orTunnelFlow:nil           // No NEPacketTunnelFlow
                      mtu:0             // Use default MTU
           messageHandler:^(NSData *request, AGDnsTunListenerReplyHandler replyHandler) {
               // Process DNS request through DnsProxy
               [proxy handleMessage:request
                           withInfo:nil
              withCompletionHandler:replyHandler];
           }
                    error:&error];
    }

    if (error || !tunListener) {
        NSLog(@"Failed to initialize TunListener: %@", error);
        [proxy stop];
        close(tun_fd);
        return 1;
    }
    
    NSLog(@"TunListener initialized successfully in %@ mode", external_mode ? @"EXTERNAL" : @"AUTONOMOUS");

    while (getchar() != 's') {
        ;
    }
    
    [tunListener stop];
    [proxy stop];
    close(tun_fd);
    return 0;
}
