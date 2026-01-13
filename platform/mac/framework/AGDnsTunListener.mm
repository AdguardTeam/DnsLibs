#import "AGDnsTunListener.h"
#import "AGDnsProxy.h"

#include "dns/proxy/tun_listener.h"
#include "common/logger.h"
#include "tcpip/utils.h"

using namespace ag::dns;

// Error domain for AGDnsTunListener
static NSString *const AGDnsTunListenerErrorDomain = @"com.adguard.dnsproxy.tunlistener";

// Destructor for NSData packets - releases the retained NSData object
static void NSData_Packet_destructor(void *arg, uint8_t *) {
    @autoreleasepool {
        NSData *data = (__bridge_transfer NSData *) arg;
        (void) data;  // Will be released when autoreleasepool drains
    }
}

// Private methods
@interface AGDnsTunListener ()
- (void)handlePackets:(NSArray<NSData *> *)packets;
@end

@implementation AGDnsTunListener {
    TunListener *_listener;
    AGDnsTunListenerMessageHandler _handler;
    NEPacketTunnelFlow *_tunnelFlow;
    void (^_readPacketsHandler)(NSArray<NSData *> *, NSArray<NSNumber *> *);
    int _tunFd;
}

- (nullable instancetype)initWithTunFd:(nullable NSNumber *)fd
                          orTunnelFlow:(nullable NEPacketTunnelFlow *)tunnelFlow
                                   mtu:(int)mtu
                        messageHandler:(AGDnsTunListenerMessageHandler)handler
                                 error:(NSError **)error {
    self = [super init];
    if (!self) {
        return nil;
    }

    if (!handler) {
        if (error) {
            *error = [NSError errorWithDomain:AGDnsTunListenerErrorDomain
                                         code:TunListener::IE_INVALID_CALLBACK
                                     userInfo:@{NSLocalizedDescriptionKey: @"Message handler is required"}];
        }
        return nil;
    }

    _handler = handler;
    _tunnelFlow = tunnelFlow;
    _listener = new TunListener();
    _tunFd = fd ? fd.intValue : -1;

    // Initialize C++ TunListener
    auto init_result = _listener->init(_tunFd, mtu,
        [self](ag::Uint8View request, TunListener::Completion completion) {
            @autoreleasepool {
                // Copy request data because it's only valid during this callback execution.
                // The handler may process it asynchronously and call replyHandler later.
                NSData *requestData = [NSData dataWithBytes:request.data() length:request.size()];
                
                // The replyHandler block captures completion by value, allowing it to be
                // called asynchronously. The completion callback will copy reply data
                // immediately when invoked, so reply.bytes only needs to be valid during
                // the completion call.
                _handler(requestData, ^(NSData *reply) {
                    if (reply) {
                        completion(ag::Uint8View{(const uint8_t *)reply.bytes, reply.length});
                    } else {
                        completion(ag::Uint8View{});
                    }
                });
            }
        },
        _tunFd == -1 ? [self](ag::Uint8View packet) {
            @autoreleasepool {
                if (_tunnelFlow) {
                    // Determine protocol from IP version byte
                    const uint8_t *data = packet.data();
                    size_t size = packet.size();
                    
                    NSNumber *protocol;
                    if (size > 0) {
                        uint8_t version = (data[0] >> 4) & 0x0F;
                        protocol = @(version == 4 ? AF_INET : AF_INET6);
                    } else {
                        protocol = @(AF_INET);
                    }
                    
                    NSData *packetData = [NSData dataWithBytes:data length:size];
                    [_tunnelFlow writePackets:@[packetData] withProtocols:@[protocol]];
                }
            }
        } : TunListener::OutputCallback{});

    if (init_result) {
        if (error) {
            NSString *errorMessage = [NSString stringWithUTF8String:init_result->str().c_str()];
            *error = [NSError errorWithDomain:AGDnsTunListenerErrorDomain
                                         code:(NSInteger)init_result->value()
                                     userInfo:@{NSLocalizedDescriptionKey: errorMessage}];
        }
        delete _listener;
        _listener = nullptr;
        return nil;
    }

    // Start reading packets if in external mode with tunnelFlow
    if (_tunFd == -1 && _tunnelFlow) {
        __weak AGDnsTunListener *weakSelf = self;
        _readPacketsHandler = ^(NSArray<NSData *> *packets, NSArray<NSNumber *> *protocols) {
            AGDnsTunListener *strongSelf = weakSelf;
            if (!strongSelf) {
                return;
            }
            
            [strongSelf handlePackets:packets];
            
            // Continue reading
            [strongSelf->_tunnelFlow readPacketsWithCompletionHandler:strongSelf->_readPacketsHandler];
        };
        
        [_tunnelFlow readPacketsWithCompletionHandler:_readPacketsHandler];
    }

    return self;
}

- (void)handlePackets:(NSArray<NSData *> *)packets {
    if (!_listener) {
        return;
    }

    // Build Packets structure with destructor callbacks to manage NSData lifetime
    // Use __bridge_retained to keep NSData alive until tcpip stack finishes processing
    ag::Packets nativePackets = {};
    nativePackets.size = (uint32_t)[packets count];
    ag::Packet buf[nativePackets.size];
    nativePackets.data = buf;
    
    for (size_t i = 0; i < nativePackets.size; ++i) {
        nativePackets.data[i] = ag::Packet{
            .data = (uint8_t *)packets[i].bytes,
            .size = packets[i].length,
            .destructor = NSData_Packet_destructor,
            .destructor_arg = (__bridge_retained void *)packets[i]
        };
    }

    _listener->handle_packets(nativePackets);
}

- (void)stop {
    if (_listener) {
        _listener->deinit();
        delete _listener;
        _listener = nullptr;
    }
    _handler = nil;
    _tunnelFlow = nil;
    _readPacketsHandler = nil;
}

- (void)dealloc {
    [self stop];
}

@end
