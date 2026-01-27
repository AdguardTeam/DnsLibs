#import "AGDnsAppProxyFlowManager.h"

#import "network_extension_utils.h"

#include "dns/net/tcp_dns_buffer.h"

#import <Network/Network.h>

#include <errno.h>
#include <netinet/in.h>

static ag::Logger g_logger("AGDnsAppProxyFlowManager");

@class AGDnsAppProxyFlowManager;

/** Return `true` if `pkt` is a DNS response, `false` in all other cases. */
inline bool is_response(ag::Uint8View pkt) {
    if (pkt.size() >= 3) {
        // Return the value of the QR bit
        return pkt[2] & 0x80; // NOLINT(*-avoid-magic-numbers)
    }
    return false;
}

@interface AGDnsAppProxySocketEntry : NSObject

@property(nonatomic, assign) int fd;
@property(nonatomic) dispatch_source_t readSource;
@property(nonatomic) dispatch_source_t writeSource;
@property(nonatomic) NSMutableData *pendingWrite;
@property(nonatomic) NWEndpoint *endpoint;

@end

@implementation AGDnsAppProxySocketEntry
@end

@interface AGDnsAppProxyTCPFlowHandler : NSObject

- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithDnsProxy:(AGDnsProxy *)dnsProxy
                         manager:(AGDnsAppProxyFlowManager *)manager
                            flow:(NEAppProxyTCPFlow *)flow
                            mode:(AGDnsAppProxyFlowMode)mode NS_DESIGNATED_INITIALIZER;

- (void)stop;

@end

@interface AGDnsAppProxyUDPFlowHandler : NSObject

- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithDnsProxy:(AGDnsProxy *)dnsProxy
                         manager:(AGDnsAppProxyFlowManager *)manager
                            flow:(NEAppProxyUDPFlow *)flow
                            mode:(AGDnsAppProxyFlowMode)mode NS_DESIGNATED_INITIALIZER;

- (void)stop;

@end

@implementation AGDnsAppProxyFlowManager {
    AGDnsProxy *_dnsProxy;
    NSMutableSet<id> *_flowHandlers;
}

- (instancetype)initWithDnsProxy:(AGDnsProxy *)dnsProxy {
    self = [super init];
    if (self) {
        _dnsProxy = dnsProxy;
        _flowHandlers = [NSMutableSet set];
    }
    return self;
}

- (BOOL)handleAppProxyFlow:(NEAppProxyFlow *)flow mode:(AGDnsAppProxyFlowMode)mode {
    if ([flow isKindOfClass:NEAppProxyTCPFlow.class]) {
        AGDnsAppProxyTCPFlowHandler *handler =
                [[AGDnsAppProxyTCPFlowHandler alloc] initWithDnsProxy:_dnsProxy
                                                              manager:self
                                                                 flow:(NEAppProxyTCPFlow *) flow
                                                                 mode:mode];
        [_flowHandlers addObject:handler];
        return YES;
    }
    if ([flow isKindOfClass:NEAppProxyUDPFlow.class]) {
        AGDnsAppProxyUDPFlowHandler *handler =
                [[AGDnsAppProxyUDPFlowHandler alloc] initWithDnsProxy:_dnsProxy
                                                              manager:self
                                                                 flow:(NEAppProxyUDPFlow *) flow
                                                                 mode:mode];
        [_flowHandlers addObject:handler];
        return YES;
    }
    return NO;
}

- (void)removeFlowHandler:(id)handler {
    if (handler) {
        [_flowHandlers removeObject:handler];
    }
}

- (void)stop {
    NSSet<id> *handlers = [_flowHandlers copy];
    for (id handler in handlers) {
        [handler stop];
    }
    [_flowHandlers removeAllObjects];
}

@end

@implementation AGDnsAppProxyTCPFlowHandler {
    ag::dns::TcpDnsBuffer _egressBuffer;
    ag::dns::TcpDnsBuffer _ingressBuffer;
    __weak AGDnsProxy *_dnsProxy;
    __weak AGDnsAppProxyFlowManager *_manager;
    NEAppProxyTCPFlow *_flow;
    void (^_readHandler)(NSData *_Nullable data, NSError *_Nullable error);
    AGDnsAppProxyFlowMode _mode;
    dispatch_queue_t _queue;
    AGDnsAppProxySocketEntry *_socket;
    BOOL _stopping;
}

- (instancetype)initWithDnsProxy:(AGDnsProxy *)dnsProxy
                         manager:(AGDnsAppProxyFlowManager *)manager
                            flow:(NEAppProxyTCPFlow *)flow
                            mode:(AGDnsAppProxyFlowMode)mode
{
    self = [super init];
    if (self) {
        _dnsProxy = dnsProxy;
        _manager = manager;
        _flow = flow;
        _mode = mode;
        _queue = dispatch_queue_create("com.adguard.dnslibs.appproxy.tcpflow", DISPATCH_QUEUE_SERIAL);
        dispatch_queue_t queue = _queue;
        __weak AGDnsAppProxyTCPFlowHandler *weakSelf = self;
        _readHandler = ^(NSData *_Nullable data, NSError *_Nullable error) {
            dispatch_async(queue, ^{
                AGDnsAppProxyTCPFlowHandler *strongSelf = weakSelf;
                if (!strongSelf || strongSelf->_stopping) {
                    return;
                }
                [strongSelf handleTcpData:data error:error];
            });
        };
        [self start];
    }
    return self;
}

- (void)start {
    __weak AGDnsAppProxyTCPFlowHandler *weakSelf = self;
    [_flow openWithLocalEndpoint:nil
               completionHandler:^(NSError *error) {
                   if (error) {
                       [weakSelf stop];
                       return;
                   }
                   if (AGDnsAppProxyTCPFlowHandler *strongSelf = weakSelf) {
                       [strongSelf readNext];
                   }
               }];
}

- (void)writeFramedPacketToFlow:(ag::Uint8View)packet {
    uint16_t length = htons((uint16_t) packet.size());
    NSMutableData *framed = [NSMutableData dataWithCapacity:sizeof(length) + packet.size()];
    [framed appendBytes:&length length:sizeof(length)];
    [framed appendBytes:packet.data() length:packet.size()];
    __weak AGDnsAppProxyTCPFlowHandler *weakSelf = self;
    [_flow writeData:framed withCompletionHandler:^(NSError *_Nullable writeError) {
        (void) writeError;
        (void) weakSelf;
    }];
}

- (void)enqueueFramedPacketToBypassSocket:(ag::Uint8View)packet {
    if (_stopping) {
        return;
    }
    if (!_socket || _socket.fd < 0) {
        [self startBypassConnection];
    }
    if (_stopping || !_socket || _socket.fd < 0) {
        return;
    }
    uint16_t length = htons((uint16_t) packet.size());
    [_socket.pendingWrite appendBytes:&length length:sizeof(length)];
    [_socket.pendingWrite appendBytes:packet.data() length:packet.size()];
}

- (void)startBypassConnection {
    NWEndpoint *remoteEndpoint = _flow.remoteEndpoint;

    sockaddr_storage remote_addr = {};
    socklen_t remote_addr_len = 0;
    if (!ag::ne_utils::sockaddr_from_nwendpoint(remoteEndpoint, AF_UNSPEC, false, &remote_addr, &remote_addr_len)) {
        [self stop];
        return;
    }

    int family = (int) remote_addr.ss_family;
    int fd = ag::ne_utils::make_nonblocking_socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        [self stop];
        return;
    }

    if (@available(macOS 10.15.4, iOS 13.4, tvOS 13.4, *)) {
        if (!ag::ne_utils::set_outbound_interface(fd, family, _flow.networkInterface)) {
            warnlog(g_logger, "Failed to set outbound interface for bypass TCP socket");
        }
    }

    int rc = connect(fd, (const sockaddr *) &remote_addr, remote_addr_len);
    if (rc != 0 && errno != EINPROGRESS) {
        close(fd);
        [self stop];
        return;
    }

    _socket = [[AGDnsAppProxySocketEntry alloc] init];
    _socket.fd = fd;
    _socket.pendingWrite = [NSMutableData data];
    _socket.endpoint = remoteEndpoint;

    __weak AGDnsAppProxyTCPFlowHandler *weakSelf = self;
    _socket.readSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t) fd, 0, _queue);
    dispatch_source_set_event_handler(_socket.readSource, ^{
        AGDnsAppProxyTCPFlowHandler *strongSelf = weakSelf;
        if (!strongSelf || strongSelf->_stopping) {
            return;
        }
        [strongSelf receiveFromBypassSocket];
    });
    dispatch_source_set_cancel_handler(_socket.readSource, ^{
        close(fd);
    });
    dispatch_resume(_socket.readSource);
}

- (void)receiveFromBypassSocket {
    if (_stopping || !_socket || _socket.fd < 0) {
        return;
    }

    uint8_t buf[64 * 1024];
    for (;;) {
        ssize_t nread = recv(_socket.fd, buf, sizeof(buf), 0);
        if (nread > 0) {
            ag::Uint8View view{buf, (size_t) nread};
            while (!view.empty()) {
                view = _ingressBuffer.store(view);
                if (auto packet = _ingressBuffer.extract_packet()) {
                    if (_mode != AGDnsAppProxyFlowModeBypass) {
                        AGDnsMessageInfo *info = [[AGDnsMessageInfo alloc] init];
                        info.isTcp = true;
                        info.transparent = true;
                        dispatch_queue_t queue = _queue;
                        __weak AGDnsAppProxyTCPFlowHandler *weakSelf = self;
                        [_dnsProxy handleMessage:[NSData dataWithBytes:packet->data() length:packet->size()]
                                         withInfo:info
                            withCompletionHandler:^(NSData *filteredReply) {
                                dispatch_async(queue, ^{
                                    AGDnsAppProxyTCPFlowHandler *strongSelf = weakSelf;
                                    if (!strongSelf || strongSelf->_stopping) {
                                        return;
                                    }
                                    auto reply = ag::Uint8View{(const uint8_t *) filteredReply.bytes, filteredReply.length};
                                    [self writeFramedPacketToFlow:reply];
                                });
                            }];
                    } else {
                        [self writeFramedPacketToFlow:{packet->data(), packet->size()}];
                    }
                }
            }
            continue;
        }

        if (nread < 0 && errno == EINTR) {
            continue;
        }
        if (nread < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN)) {
            return;
        }
        [self stop];
        return;
    }
}

- (void)flushBypassSocketWrite {
    if (_stopping || !_socket || _socket.fd < 0) {
        return;
    }
    while (_socket.pendingWrite.length > 0) {
        ssize_t nsent = send(_socket.fd, _socket.pendingWrite.bytes, _socket.pendingWrite.length, 0);
        if (nsent > 0) {
            [_socket.pendingWrite replaceBytesInRange:NSMakeRange(0, (NSUInteger) nsent) withBytes:NULL length:0];
            continue;
        }
        if (nsent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN)) {
            if (!_socket.writeSource) {
                __weak AGDnsAppProxyTCPFlowHandler *weakSelf = self;
                _socket.writeSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE, (uintptr_t) _socket.fd, 0, _queue);
                dispatch_source_set_event_handler(_socket.writeSource, ^{
                    AGDnsAppProxyTCPFlowHandler *strongSelf = weakSelf;
                    if (!strongSelf || strongSelf->_stopping) {
                        return;
                    }
                    [strongSelf flushBypassSocketWrite];
                });
                dispatch_source_set_cancel_handler(_socket.writeSource, ^{
                });
                dispatch_resume(_socket.writeSource);
            }
            return;
        }
        if (nsent < 0 && errno == EINTR) {
            continue;
        }
        [self stop];
        return;
    }
    if (_socket.writeSource) {
        dispatch_source_cancel(_socket.writeSource);
        _socket.writeSource = nil;
    }
}

- (void)readNext {
    if (!_stopping) {
        [_flow readDataWithCompletionHandler:_readHandler];
    }
}

- (void)handleTcpData:(NSData *)data error:(NSError *)error {
    if (error || data.length == 0) {
        [self stop];
        return;
    }

    ag::Uint8View view{(const uint8_t *) data.bytes, data.length};
    while (!view.empty()) {
        view = _egressBuffer.store(view);
        if (auto packet = _egressBuffer.extract_packet()) {
            NSData *dnsMessage = [NSData dataWithBytes:packet->data() length:packet->size()];
            BOOL redirectAsFilter = (_mode == AGDnsAppProxyFlowModeRedirect)
                    && [_dnsProxy matchFallbackDomains:dnsMessage];
            if (_mode == AGDnsAppProxyFlowModeBypass) {
                [self enqueueFramedPacketToBypassSocket:{packet->data(), packet->size()}];
            } else if (_mode == AGDnsAppProxyFlowModeFilter || redirectAsFilter) {
                AGDnsMessageInfo *info = [[AGDnsMessageInfo alloc] init];
                info.isTcp = true;
                info.transparent = true;
                dispatch_queue_t queue = _queue;
                __weak AGDnsAppProxyTCPFlowHandler *weakSelf = self;
                [_dnsProxy handleMessage:dnsMessage
                                 withInfo:info
                    withCompletionHandler:^(NSData *filteredReply) {
                        dispatch_async(queue, ^{
                            AGDnsAppProxyTCPFlowHandler *strongSelf = weakSelf;
                            if (!strongSelf || strongSelf->_stopping) {
                                return;
                            }
                            auto reply = ag::Uint8View{(const uint8_t *) filteredReply.bytes, filteredReply.length};
                            if (is_response(reply)) {
                                [strongSelf writeFramedPacketToFlow:reply];
                            } else {
                                [strongSelf enqueueFramedPacketToBypassSocket:reply];
                                [strongSelf flushBypassSocketWrite];
                            }
                        });
                    }];
            } else {
                AGDnsMessageInfo *info = [[AGDnsMessageInfo alloc] init];
                info.isTcp = true;
                info.transparent = false;
                dispatch_queue_t queue = _queue;
                __weak AGDnsAppProxyTCPFlowHandler *weakSelf = self;
                [_dnsProxy handleMessage:dnsMessage
                                 withInfo:info
                    withCompletionHandler:^(NSData *reply) {
                        dispatch_async(queue, ^{
                            AGDnsAppProxyTCPFlowHandler *strongSelf = weakSelf;
                            if (!strongSelf || strongSelf->_stopping) {
                                return;
                            }
                            auto response = ag::Uint8View{(const uint8_t *) reply.bytes, reply.length};
                            [strongSelf writeFramedPacketToFlow:response];
                        });
                    }];
            }
        }
    }
    if (_mode == AGDnsAppProxyFlowModeBypass) {
        [self flushBypassSocketWrite];
    }
    [self readNext];
}

- (void)stop {
    if (_stopping) {
        return;
    }
    _stopping = YES;
    if (_socket) {
        if (_socket.readSource) {
            dispatch_source_cancel(_socket.readSource);
            _socket.readSource = nil;
        } else if (_socket.fd >= 0) {
            close(_socket.fd);
        }
        if (_socket.writeSource) {
            dispatch_source_cancel(_socket.writeSource);
            _socket.writeSource = nil;
        }
        _socket.fd = -1;
        _socket = nil;
    }
    [_flow closeReadWithError:nil];
    [_flow closeWriteWithError:nil];
    dbglog(g_logger, "AGDnsAppProxyTCPFlowHandler stopped for flow {}", _flow.description.UTF8String);
    [_manager removeFlowHandler:self];
}

@end

@implementation AGDnsAppProxyUDPFlowHandler {
    __weak AGDnsProxy *_dnsProxy;
    __weak AGDnsAppProxyFlowManager *_manager;
    NEAppProxyUDPFlow *_flow;
    void (^_readUdpDatagramHandler)(NSArray<NSData *> *_Nullable datagrams,
            NSArray<NWEndpoint *> *_Nullable remoteEndpoints, NSError *_Nullable error);
    AGDnsAppProxyFlowMode _mode;
    dispatch_queue_t _queue;
    AGDnsAppProxySocketEntry *_udpSocket;
    int _udpFamily;
    BOOL _stopping;
}

- (BOOL)sendDatagramToBypassSocket:(NSData *)datagram
                       destination:(NWEndpoint *)destination
                     stopOnFailure:(BOOL)stopOnFailure {
    if (_stopping || !destination) {
        return NO;
    }
    if (!_udpSocket || _udpSocket.fd < 0) {
        [self setupBypassUdpSocket];
    }
    if (_stopping || !_udpSocket || _udpSocket.fd < 0) {
        return NO;
    }

    sockaddr_storage remote_addr = {};
    socklen_t remote_addr_len = 0;
    if (!ag::ne_utils::sockaddr_from_nwendpoint(destination, _udpFamily, false, &remote_addr, &remote_addr_len)) {
        return NO;
    }

    ssize_t sent = sendto(_udpSocket.fd, datagram.bytes, datagram.length, 0, (const sockaddr *) &remote_addr, remote_addr_len);
    if (sent < 0 && !(errno == EAGAIN || errno == EWOULDBLOCK)) {
        if (stopOnFailure) {
            [self stop];
        }
        return NO;
    }

    return YES;
}

- (instancetype)initWithDnsProxy:(AGDnsProxy *)dnsProxy
                         manager:(AGDnsAppProxyFlowManager *)manager
                            flow:(NEAppProxyUDPFlow *)flow
                            mode:(AGDnsAppProxyFlowMode)mode
{
    self = [super init];
    if (self) {
        _dnsProxy = dnsProxy;
        _manager = manager;
        _flow = flow;
        _mode = mode;
        _queue = dispatch_queue_create("com.adguard.dnslibs.appproxy.udpflow", DISPATCH_QUEUE_SERIAL);
        _udpFamily = AF_UNSPEC;
        dispatch_queue_t queue = _queue;
        __weak AGDnsAppProxyUDPFlowHandler *weakSelf = self;
        _readUdpDatagramHandler = ^(NSArray<NSData *> *_Nullable datagrams,
                NSArray<NWEndpoint *> *_Nullable remoteEndpoints, NSError *_Nullable error) {
            dispatch_async(queue, ^{
                AGDnsAppProxyUDPFlowHandler *strongSelf = weakSelf;
                if (!strongSelf || strongSelf->_stopping) {
                    return;
                }
                [strongSelf handleUdpDatagrams:datagrams remoteEndpoints:remoteEndpoints error:error];
            });
        };
        [self start];
    }
    return self;
}

- (void)start {
    __weak AGDnsAppProxyUDPFlowHandler *weakSelf = self;
    [_flow openWithLocalEndpoint:nil
               completionHandler:^(NSError *error) {
                   if (error) {
                       [weakSelf stop];
                       return;
                   }
                   if (AGDnsAppProxyUDPFlowHandler *strongSelf = weakSelf) {
                       [strongSelf readNext];
                   }
               }];
}

- (void)setupBypassUdpSocket {
    if (_stopping || _udpSocket) {
        return;
    }

    sockaddr_storage local_address = {};
    socklen_t local_address_len = 0;
    if (!ag::ne_utils::get_flow_local_address(_flow, &local_address, &local_address_len)) {
        [self stop];
        return;
    }

    _udpFamily = (int) local_address.ss_family;
    int fd = ag::ne_utils::make_nonblocking_socket(_udpFamily, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        [self stop];
        return;
    }

    if (@available(macOS 10.15.4, iOS 13.4, tvOS 13.4, *)) {
        if (!ag::ne_utils::set_outbound_interface(fd, _udpFamily, _flow.networkInterface)) {
            warnlog(g_logger, "Failed to set outbound interface for bypass UDP socket");
        }
    }

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    if (bind(fd, (const sockaddr *) &local_address, local_address_len) != 0) {
        close(fd);
        [self stop];
        return;
    }

    _udpSocket = [[AGDnsAppProxySocketEntry alloc] init];
    _udpSocket.fd = fd;

    __weak AGDnsAppProxyUDPFlowHandler *weakSelf = self;
    _udpSocket.readSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t) fd, 0, _queue);
    dispatch_source_set_event_handler(_udpSocket.readSource, ^{
        AGDnsAppProxyUDPFlowHandler *strongSelf = weakSelf;
        if (!strongSelf || strongSelf->_stopping) {
            return;
        }
        [strongSelf receiveFromUdpSocket];
    });
    dispatch_source_set_cancel_handler(_udpSocket.readSource, ^{
        close(fd);
    });
    dispatch_resume(_udpSocket.readSource);
}

- (void)readNext {
    if (!_stopping) {
        [_flow readDatagramsWithCompletionHandler:_readUdpDatagramHandler];
    }
}

- (void)handleUdpDatagrams:(NSArray<NSData *> *_Nullable)datagrams
           remoteEndpoints:(NSArray<NWEndpoint *> *_Nullable)remoteEndpoints
                     error:(NSError *_Nullable)error {
    if (error || datagrams.count == 0 || remoteEndpoints.count == 0) {
        [self stop];
        return;
    }

    for (size_t index = 0; index < datagrams.count; index++) {
        NSData *datagram = datagrams[index];
        NWEndpoint *_Nullable destination = remoteEndpoints[index];

        if (!destination) {
            continue;
        }

        BOOL redirectAsFilter = (_mode == AGDnsAppProxyFlowModeRedirect)
                && [_dnsProxy matchFallbackDomains:datagram];

        if (_mode == AGDnsAppProxyFlowModeBypass) {
            if (![self sendDatagramToBypassSocket:datagram destination:destination stopOnFailure:YES]) {
                return;
            }
        } else if (_mode == AGDnsAppProxyFlowModeFilter || redirectAsFilter) {
            AGDnsMessageInfo *info = [[AGDnsMessageInfo alloc] init];
            info.isTcp = false;
            info.transparent = true;
            dispatch_queue_t queue = _queue;
            __weak AGDnsAppProxyUDPFlowHandler *weakSelf = self;
            [_dnsProxy handleMessage:datagram
                             withInfo:info
                withCompletionHandler:^(NSData *filteredReply) {
                    dispatch_async(queue, ^{
                        AGDnsAppProxyUDPFlowHandler *strongSelf = weakSelf;
                        if (!strongSelf || strongSelf->_stopping) {
                            return;
                        }
                        auto reply = ag::Uint8View{(const uint8_t *) filteredReply.bytes, filteredReply.length};
                        if (is_response(reply)) {
                            [strongSelf->_flow writeDatagrams:@[ filteredReply ]
                                              sentByEndpoints:@[ destination ]
                                            completionHandler:^(NSError *_Nullable /* error */) {
                                            }];
                        } else {
                            (void) [strongSelf sendDatagramToBypassSocket:filteredReply destination:destination stopOnFailure:YES];
                        }
                    });
                }];
        } else {
            __weak AGDnsAppProxyUDPFlowHandler *weakSelf = self;
            dispatch_queue_t queue = _queue;
            [_dnsProxy handleMessage:datagram
                             withInfo:nil
                withCompletionHandler:^(NSData *reply) {
                    dispatch_async(queue, ^{
                        AGDnsAppProxyUDPFlowHandler *strongSelf = weakSelf;
                        if (!strongSelf || strongSelf->_stopping) {
                            return;
                        }
                        [strongSelf->_flow writeDatagrams:@[ reply ]
                                          sentByEndpoints:@[ destination ]
                                        completionHandler:^(NSError *_Nullable /* error */) {
                                        }];
                    });
                }];
        }
    }
    [self readNext];
}

- (void)receiveFromUdpSocket {
    if (_stopping || !_udpSocket || _udpSocket.fd < 0) {
        return;
    }

    uint8_t buf[64 * 1024];
    for (;;) {
        sockaddr_storage from = {};
        socklen_t from_len = sizeof(from);
        ssize_t nread = recvfrom(_udpSocket.fd, buf, sizeof(buf), 0, (sockaddr *) &from, &from_len);
        if (nread >= 0) {
            NWEndpoint *endpoint = ag::ne_utils::nwendpoint_from_sockaddr((const sockaddr *) &from, from_len);
            if (!endpoint) {
                continue;
            }

            NSData *data = [NSData dataWithBytes:buf length:(NSUInteger) nread];

            if (_mode != AGDnsAppProxyFlowModeBypass) {
                AGDnsMessageInfo *info = [[AGDnsMessageInfo alloc] init];
                info.isTcp = false;
                info.transparent = true;
                dispatch_queue_t queue = _queue;
                __weak AGDnsAppProxyUDPFlowHandler *weakSelf = self;
                [_dnsProxy handleMessage:data
                                 withInfo:info
                    withCompletionHandler:^(NSData *filteredReply) {
                        dispatch_async(queue, ^{
                            AGDnsAppProxyUDPFlowHandler *strongSelf = weakSelf;
                            if (!strongSelf || strongSelf->_stopping) {
                                return;
                            }
                            [strongSelf->_flow writeDatagrams:@[ filteredReply ]
                                              sentByEndpoints:@[ endpoint ]
                                            completionHandler:^(NSError *_Nullable writeError) {
                                                (void) writeError;
                                            }];
                        });
                    }];
            } else {
                [_flow writeDatagrams:@[ data ]
                      sentByEndpoints:@[ endpoint ]
                    completionHandler:^(NSError *_Nullable writeError) {
                        (void) writeError;
                    }];
            }
            continue;
        }

        if (nread < 0 && errno == EINTR) {
            continue;
        }
        if (nread < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        }
        [self stop];
        return;
    }
}

- (void)stop {
    if (_stopping) {
        return;
    }
    _stopping = YES;
    if (_udpSocket) {
        if (_udpSocket.readSource) {
            dispatch_source_cancel(_udpSocket.readSource);
            _udpSocket.readSource = nil;
        } else if (_udpSocket.fd >= 0) {
            close(_udpSocket.fd);
        }
        _udpSocket.fd = -1;
        _udpSocket = nil;
    }
    [_flow closeReadWithError:nil];
    [_flow closeWriteWithError:nil];
    dbglog(g_logger, "AGDnsAppProxyUDPFlowHandler stopped for flow {}", _flow.description.UTF8String);
    [_manager removeFlowHandler:self];
}

@end
