#pragma once

#ifdef __ANDROID__

#include <cstdint>
#include <optional>
#include <string_view>
#include <jni.h>
#include "jni_utils.h"

// Forward declaration to avoid including multinetwork.h
typedef uint64_t net_handle_t;

namespace ag::dns {

/**
 * Android Context Manager for network interface operations.
 * Provides integration with Android ConnectivityManager through JNI.
 */
class AndroidContextManager {
public:
    AndroidContextManager() = delete;
    AndroidContextManager(const AndroidContextManager &) = delete;
    AndroidContextManager(AndroidContextManager &&) = delete;
    AndroidContextManager &operator=(const AndroidContextManager &) = delete;
    AndroidContextManager &operator=(AndroidContextManager &&) = delete;
    ~AndroidContextManager() = delete;

    /**
     * Get network handle for a specific network interface.
     * @param interface_name Network interface name (e.g., "eth0", "wlan0")
     * @return Network handle if found, std::nullopt otherwise
     */
    static std::optional<net_handle_t> get_network_handle_for_interface(std::string_view interface_name);

    /**
     * Initialize the context manager with Java VM reference.
     * Should be called during JNI initialization.
     * @param vm Java VM pointer
     */
    static void initialize(JavaVM *vm);

    /**
     * Set Android application context for network operations.
     * @param context Android Context object (jobject)
     */
    static void set_application_context(jobject context);

private:

    /**
     * Get ConnectivityManager from Android context.
     * @return ConnectivityManager GlobalRef or empty GlobalRef
     */
    static ag::jni::GlobalRef<jobject> get_connectivity_manager();

    /**
     * Get network handle for interface using ConnectivityManager.
     * @param connectivity_manager ConnectivityManager instance
     * @param interface_name Network interface name
     * @return Network handle if found, std::nullopt otherwise
     */
    static std::optional<net_handle_t> get_network_handle_from_connectivity_manager(
            const ag::jni::GlobalRef<jobject> &connectivity_manager, std::string_view interface_name);
};

} // namespace ag::dns

#endif // __ANDROID__
