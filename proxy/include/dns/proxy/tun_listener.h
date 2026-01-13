#pragma once

#include <functional>
#include <memory>

#include "common/defs.h"
#include "common/error.h"
#include "dns/common/event_loop.h"
#include "tcpip/tcpip.h"

namespace ag::dns {

/**
 * This class provides an interface for handling network traffic
 * from a TUN device. It processes TCP and UDP connections, extracts raw
 * packet data, and delivers it to the user via a callback.
 * 
 * The user is responsible for processing the data and providing a response
 * through the Completion callback.
 */
class TunListener {
public:
    /**
     * Completion callback type for responding to requests
     * 
     * This callback must be invoked with the response data. It may be called
     * asynchronously on any thread. The implementation will copy the reply data
     * immediately, so the caller does not need to keep it alive after the call.
     * 
     * @param reply The response data to send back
     */
    using Completion = std::function<void(Uint8View reply)>;

    /**
     * Request callback type
     * 
     * This callback is invoked when a DNS request is received from the TUN device.
     * The callback may process the request asynchronously and invoke the completion
     * callback at any time, on any thread. The request data is only valid during
     * the callback execution, so it must be copied if needed later.
     * 
     * @param request The incoming request data (valid only during callback execution)
     * @param completion Callback to invoke with the response (may be called asynchronously)
     */
    using RequestCallback = std::function<void(Uint8View request, Completion completion)>;

    /**
     * Output callback type for sending packets back to TUN device (external mode)
     * @param packet The packet to send
     */
    using OutputCallback = std::function<void(Uint8View packet)>;

    enum InitError : uint8_t  {
        IE_INVALID_FD,           /**< Invalid file descriptor */
        IE_INVALID_MTU,          /**< Invalid MTU value */
        IE_INVALID_CALLBACK,     /**< Invalid callback */
        IE_TCPIP_INIT_FAILED,    /**< Failed to initialize tcpip stack */
    };

    TunListener();
    ~TunListener();

    TunListener(const TunListener &) = delete;
    TunListener &operator=(const TunListener &) = delete;
    TunListener(TunListener &&) = delete;
    TunListener &operator=(TunListener &&) = delete;

    /**
     * Initialize the TUN listener
     * @param fd File descriptor of TUN device (use -1 for external mode)
     *           fd >= 0: Autonomous mode (with tcpip stack)
     *           fd == -1: External mode (packets via handle_packets/output_callback)
     * @param mtu MTU size (0 = use default)
     * @param request_callback Callback for DNS requests
     * @param output_callback Callback for sending packets back (required if fd == -1, ignored otherwise)
     * @return nullopt if successful, error otherwise
     */
    [[nodiscard]] Error<InitError> init(
            int fd, int mtu, RequestCallback request_callback, OutputCallback output_callback = nullptr);

    /**
     * Handle incoming packets from external source (external mode only)
     * @param packets Array of raw IP packets (without TUN headers)
     */
    void handle_packets(Packets packets);

    /**
     * Deinitialize the TUN listener
     */
    void deinit();

private:
    struct Impl;
    std::unique_ptr<Impl> m_pimpl;

    void process_packets(Packets packets);
};

} // namespace ag::dns

namespace ag {

template <>
struct ErrorCodeToString<dns::TunListener::InitError> {
    std::string operator()(dns::TunListener::InitError e) {
        switch (e) {
        case dns::TunListener::IE_INVALID_FD: return "Invalid file descriptor";
        case dns::TunListener::IE_INVALID_MTU: return "Invalid MTU";
        case dns::TunListener::IE_INVALID_CALLBACK: return "Callback is null";
        case dns::TunListener::IE_TCPIP_INIT_FAILED: return "Failed to initialize tcpip stack";
        default: return "Unknown error";
        }
    }
};

} // namespace ag
