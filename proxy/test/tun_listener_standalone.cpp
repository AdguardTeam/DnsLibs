/**
 * TUN Listener Test Application
 * 
 * This application demonstrates how to use DnsProxy with a TUN device to intercept
 * and handle DNS traffic at the IP packet level.
 *
 * REQUIREMENTS:
 * - Root privileges (sudo) - required to create TUN device and configure routes
 * - macOS or Linux operating system
 * 
 * MODES:
 * 1. Autonomous mode (default): TunListener manages TUN device internally
 * 2. External mode: Application reads from TUN and feeds packets via handle_packets()
 * 
 * WHAT IT DOES:
 * 1. Creates a TUN device (utunX on macOS, tunX on Linux)
 * 2. Configures the interface with IP addresses:
 *    - Local:  198.18.53.1
 *    - Remote: 198.18.53.53 (DNS server address)
 * 3. Adds a route to direct traffic to 198.18.53.53 through the TUN device
 * 4. Starts DnsProxy with TUN listener
 * 5. Waits for DNS queries and handles them
 * 
 * HOW TO TEST:
 *   # Autonomous mode (default):
 *   sudo ./tun_listener_standalone
 *   
 *   # External mode:
 *   sudo ./tun_listener_standalone --external
 *   
 *   # In another terminal, send DNS queries to the TUN interface:
 *   dig example.com @198.18.53.53
 *   dig example.com +tcp @198.18.53.53
 *   
 *   # Test filtering (evil.com and evil.org are blocked):
 *   dig evil.com @198.18.53.53
 *   dig evil.org @198.18.53.53
 */

#include <atomic>
#include <cassert>
#include <chrono>
#include <csignal>
#include <cstring>
#include <thread>
#include <string>
#include <string_view>
#include <vector>
#include <cerrno>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif // _WIN32

#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#elif __APPLE__
#include <net/if.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/kern_event.h>
#include <common/utils.h>

// macOS utun definitions
#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#define UTUN_OPT_IFNAME 2
#endif

#include "common/logger.h"
#include "common/error.h"
#include "dns/proxy/dnsproxy.h"
#include "dns/proxy/tun_listener.h"
#include "tcpip/utils.h"

using namespace ag::dns;
static const ag::Logger g_logger{"tun_listener_standalone"};

static_assert(std::atomic_bool::is_always_lock_free, "Atomic bools are not always lock-free");
static std::atomic_bool keep_running{true};

static void sigint_handler(int signal) {
    assert(signal == SIGINT);
    keep_running = false;
}

#ifdef __APPLE__
// macOS TUN device setup
static int create_tun_device(std::string &dev_name) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        errlog(g_logger, "socket(SYSPROTO_CONTROL)");
        return -1;
    }

    struct ctl_info info = {};
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
    if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
        errlog(g_logger, "ioctl(CTLIOCGINFO)");
        close(fd);
        return -1;
    }

    struct sockaddr_ctl addr = {};
    addr.sc_id = info.ctl_id;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = 0; // 0 means allocate next available

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        errlog(g_logger, "connect(AF_SYS_CONTROL)");
        close(fd);
        return -1;
    }

    // Get the actual interface name
    char utunname[IFNAMSIZ];
    socklen_t utunname_len = sizeof(utunname);
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, utunname, &utunname_len) < 0) {
        errlog(g_logger, "getsockopt(UTUN_OPT_IFNAME)");
        close(fd);
        return -1;
    }
    dev_name = utunname;

    return fd;
}

static bool configure_tun_interface(std::string_view tun_name,
        std::string_view local_addr, std::string_view remote_addr) {
    std::string cmd = AG_FMT("ifconfig {} {} {} up", tun_name, local_addr, remote_addr);

    tracelog(g_logger, "Executing: {}", cmd);
    if (system(cmd.c_str()) != 0) {
        errlog(g_logger, "Failed to configure interface");
        return false;
    }

    // Add route to DNS server
    cmd = AG_FMT("route add -host {} -interface {}", remote_addr, tun_name);
    tracelog(g_logger, "Executing: {}", cmd);
    if (system(cmd.c_str()) != 0) {
        errlog(g_logger, "Failed to add route");
        return false;
    }

    return true;
}

#elif __linux__
// Linux TUN device setup
static int create_tun_device(std::string &dev_name) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        errlog(g_logger, "open(/dev/net/tun)");
        return -1;
    }

    struct ifreq ifr = {};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    // Leave ifr_name empty - kernel will allocate next available tunX

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        errlog(g_logger, "ioctl(TUNSETIFF)");
        close(fd);
        return -1;
    }

    // Get the actual interface name assigned by kernel
    dev_name = ifr.ifr_name;

    return fd;
}

static bool configure_tun_interface(std::string_view tun_name,
        std::string_view local_addr, std::string_view remote_addr) {
    std::string cmd = AG_FMT("ip addr add {} peer {} dev {}", local_addr, remote_addr, tun_name);
    
    tracelog(g_logger, "Executing: {}", cmd);
    if (system(cmd.c_str()) != 0) {
        errlog(g_logger, "Failed to configure interface");
        return false;
    }

    // Bring interface up
    cmd = AG_FMT("ip link set {} up", tun_name);
    tracelog(g_logger, "Executing: {}", cmd);
    if (system(cmd.c_str()) != 0) {
        errlog(g_logger, "Failed to bring interface up");
        return false;
    }

    return true;
}
#endif

int main(int argc, char *argv[]) {
    ag::Logger::set_log_level(ag::LogLevel::LOG_LEVEL_TRACE);
    
    // Parse command line arguments
    bool external_mode = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--external" || std::string_view(argv[i]) == "-e") {
            external_mode = true;
        } else if (std::string_view(argv[i]) == "--help" || std::string_view(argv[i]) == "-h") {
            infolog(g_logger, "Usage: {} [--external|-e]", argv[0]);
            infolog(g_logger, "  --external, -e  Use external mode (packets via handle_packets)");
            return 0;
        }
    }
    
#ifdef _WIN32
    // TUN is not supported on Windows
    errlog(g_logger, "TUN listener is not supported on Windows");
    return 1;
#else
    using namespace std::chrono_literals;

#ifdef __APPLE__
    std::string tun_name; // Will be filled by create_tun_device
    int tun_fd = create_tun_device(tun_name);
#elif __linux__
    std::string tun_name; // Will be filled by create_tun_device (kernel allocates next available)
    int tun_fd = create_tun_device(tun_name);
#else
    errlog(g_logger, "Unsupported platform");
    return 1;
#endif

    if (tun_fd < 0) {
        errlog(g_logger, "Failed to create TUN device");
        return 1;
    }

    infolog(g_logger, "TUN device created: {} (fd={})", tun_name, tun_fd);

    // Configure TUN interface
    const std::string_view local_addr = "198.18.53.1";
    const std::string_view remote_addr = "198.18.53.53";
    
    if (!configure_tun_interface(tun_name, local_addr, remote_addr)) {
        close(tun_fd);
        return 1;
    }

    dbglog(g_logger, "TUN interface configured successfully. Local address: {}. Remote address: {}",
            local_addr, remote_addr);

    // Setup DnsProxy
    DnsProxySettings settings = DnsProxySettings::get_default();
    
    // Configure upstream DNS server
    settings.upstreams = {{
            .address = "94.140.14.14",
            .bootstrap = {},
            .resolved_server_ip = std::monostate{},
            .id = 42,
            .outbound_interface = std::monostate{},
            .ignore_proxy_settings = false,
    }};

    // Add some filtering for testing
    settings.filter_params = {{
            {
                    .id = 42,
                    .data = "0.0.0.0 evil.com\n",
                    .in_memory = true,
            },
            {
                    .id = 43,
                    .data = "||evil.org^\n",
                    .in_memory = true,
            },
    }};

    settings.dns_cache_size = 0;
    settings.optimistic_cache = false;
    settings.enable_http3 = false;

    dbglog(g_logger, "Initializing DnsProxy");
    DnsProxy proxy;
    auto [ret, err] = proxy.init(settings, {});
    if (!ret) {
        errlog(g_logger, "Failed to initialize DnsProxy: {}", err->pretty_str());
        close(tun_fd);
        return 1;
    }

    infolog(g_logger, "DnsProxy initialized successfully!");

    // Create TunListener
    dbglog(g_logger, "Initializing TunListener in {} mode", external_mode ? "EXTERNAL" : "AUTONOMOUS");

    TunListener::RequestCallback request_callback
            = [&proxy](ag::Uint8View request, TunListener::Completion completion) {
                // Process DNS request through DnsProxy
                auto reply = proxy.handle_message_sync(request, nullptr);
                completion(ag::Uint8View{reply.data(), reply.size()});
            };

    TunListener tun_listener;
    ag::Error<TunListener::InitError> tun_result;
    
    if (external_mode) {
        // External mode: we read packets and feed them to TunListener
        tun_result = tun_listener.init(-1, 0, request_callback,
            [tun_fd](ag::Uint8View packet) {
                // Write packet back to TUN device
                // On macOS, need to add utun header (4 bytes: address family in network byte order)
#ifdef __APPLE__
                // Determine family from IP version
                int family = AF_INET;
                if (packet.size() > 0) {
                    uint8_t version = (packet.data()[0] >> 4) & 0x0F;
                    family = (version == 4) ? AF_INET : AF_INET6;
                }
                uint32_t family_be = htonl(family);
                
                std::vector<uint8_t> buffer;
                buffer.insert(buffer.end(), (uint8_t*)&family_be, (uint8_t*)&family_be + sizeof(family_be));
                buffer.insert(buffer.end(), packet.data(), packet.data() + packet.size());
                
                ssize_t written = write(tun_fd, buffer.data(), buffer.size());
#else
                ssize_t written = write(tun_fd, packet.data(), packet.size());
#endif
                if (written < 0) {
                    errlog(g_logger, "Failed to write packet to TUN device: {}", strerror(errno));
                } else {
                    tracelog(g_logger, "Wrote {} bytes to TUN device", written);
                }
            });
    } else {
        // Autonomous mode: TunListener manages TUN device
        tun_result = tun_listener.init(tun_fd, 0, request_callback);
    }

    if (tun_result) {
        errlog(g_logger, "Failed to initialize TunListener: {}", tun_result->str());
        proxy.deinit();
        close(tun_fd);
        return 1;
    }

    infolog(g_logger, "TunListener initialized successfully! Mode: {}", external_mode ? "EXTERNAL" : "AUTONOMOUS");

    std::signal(SIGINT, sigint_handler);
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif

    if (external_mode) {
        // External mode: read packets from TUN device and feed to TunListener
        infolog(g_logger, "Starting packet reading loop (external mode)");
        
        // Set TUN fd to non-blocking
        int flags = fcntl(tun_fd, F_GETFL, 0);
        fcntl(tun_fd, F_SETFL, flags | O_NONBLOCK);
        
        std::vector<uint8_t> buffer(4096);
        
        while (keep_running) {
            ssize_t nread = read(tun_fd, buffer.data(), buffer.size());
            
            if (nread < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // No data available, sleep a bit
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
                errlog(g_logger, "Error reading from TUN device: {}", strerror(errno));
                break;
            }
            
            if (nread > 0) {
                tracelog(g_logger, "Read {} bytes from TUN device", nread);
                
                // On macOS, utun packets have 4-byte header (address family in network byte order)
                // Skip it to get the actual IP packet
                uint8_t *packet_data = buffer.data();
                size_t packet_size = (size_t)nread;
                
#ifdef __APPLE__
                constexpr size_t UTUN_HDR_SIZE = 4;
                if (packet_size < UTUN_HDR_SIZE) {
                    errlog(g_logger, "Packet too small: {} bytes (expected at least {})", packet_size, UTUN_HDR_SIZE);
                    continue;
                }
                packet_data += UTUN_HDR_SIZE;
                packet_size -= UTUN_HDR_SIZE;
                tracelog(g_logger, "Stripped utun header, packet size: {}", packet_size);
#endif
                
                // Copy packet data because handle_packets is asynchronous
                // and buffer will be reused for next packet
                auto *packet_copy = new std::vector<uint8_t>(packet_data, packet_data + packet_size);
                
                // Create Packet structure with destructor to free copied data
                ag::Packet pkt{
                    .data = packet_copy->data(),
                    .size = packet_copy->size(),
                    .destructor = [](void *arg, uint8_t *) {
                        delete static_cast<std::vector<uint8_t>*>(arg);
                    },
                    .destructor_arg = packet_copy
                };
                
                ag::Packets packets{
                    .data = &pkt,
                    .size = 1
                };
                
                // Feed packet to TunListener
                tun_listener.handle_packets(packets);
            }
        }
    } else {
        // Autonomous mode: just wait
        while (keep_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    dbglog(g_logger, "Shutting down");
    
    tun_listener.deinit();
    proxy.deinit();
    close(tun_fd);
    
    return 0;
#endif // _WIN32
}
