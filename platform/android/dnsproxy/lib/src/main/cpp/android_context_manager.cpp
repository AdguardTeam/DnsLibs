#ifdef __ANDROID__

#include <android/multinetwork.h>

#include <atomic>

#include "android_context_manager.h"
#include "common/logger.h"

#include "scoped_jni_env.h"

namespace ag::dns {

static ag::Logger g_log{"AndroidContextManager"};
static JavaVM *g_java_vm = nullptr;
static ag::jni::GlobalRef<jobject> g_app_context;
// The GlobalRef is only accessed from the MdnsClient event loop thread; the atomics mirror
// it so test/diagnostic hooks can safely observe the state from another thread.
static ag::jni::GlobalRef<jobject> g_multicast_lock;
static std::atomic<bool> g_multicast_lock_held{false};
static std::atomic<net_handle_t> g_last_bound_network_handle{0};

void AndroidContextManager::initialize(JavaVM *vm) {
    g_java_vm = vm;
    infolog(g_log, "AndroidContextManager initialized with JavaVM");
}

void AndroidContextManager::set_application_context(jobject context) {
    if (g_java_vm && context) {
        g_app_context = ag::jni::GlobalRef<jobject>(g_java_vm, context);
        infolog(g_log, "AndroidContextManager application context set");
    } else {
        errlog(g_log, "Cannot set application context: JavaVM not initialized or context is null");
    }
}

ag::jni::GlobalRef<jobject> AndroidContextManager::get_system_service(const char *name) {
    if (!g_java_vm) {
        errlog(g_log, "AndroidContextManager not initialized");
        return {};
    }

    if (!g_app_context) {
        errlog(g_log, "Application context not set");
        return {};
    }

    ag::jni::ScopedJniEnv env(g_java_vm, 8);

    jobject context = g_app_context.get();

    ag::jni::LocalRef<jclass> context_class{env.get(), env->GetObjectClass(context)};
    if (!context_class) {
        errlog(g_log, "Failed to get Context class");
        return {};
    }

    jmethodID get_system_service_method =
            env->GetMethodID(context_class.get(), "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
    if (!get_system_service_method) {
        errlog(g_log, "Failed to get getSystemService method");
        return {};
    }

    ag::jni::LocalRef<jstring> service_str{env.get(), env->NewStringUTF(name)};
    if (!service_str) {
        errlog(g_log, "Failed to create the {} service string", name);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        return {};
    }

    ag::jni::LocalRef<jobject> service{
            env.get(), env->CallObjectMethod(context, get_system_service_method, service_str.get())};
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        errlog(g_log, "Exception while calling getSystemService({})", name);
        return {};
    }
    if (!service) {
        errlog(g_log, "Failed to get the {} service", name);
        return {};
    }

    tracelog(g_log, "Successfully obtained the {} service", name);
    return ag::jni::GlobalRef<jobject>(g_java_vm, service.get());
}

ag::jni::GlobalRef<jobject> AndroidContextManager::get_connectivity_manager() {
    return get_system_service("connectivity");
}

std::optional<net_handle_t> AndroidContextManager::get_network_handle_from_connectivity_manager(
        const ag::jni::GlobalRef<jobject> &connectivity_manager, std::string_view interface_name) {

    if (!g_java_vm) {
        errlog(g_log, "AndroidContextManager not initialized");
        return std::nullopt;
    }

    ag::jni::ScopedJniEnv env(g_java_vm, 64);

    jobject connectivityManager = connectivity_manager.get();

    ag::jni::LocalRef<jclass> cmClass{env.get(), env->GetObjectClass(connectivityManager)};
    if (!cmClass) {
        errlog(g_log, "Failed to get ConnectivityManager class");
        return std::nullopt;
    }

    jmethodID getAllNetworksMethod = env->GetMethodID(cmClass.get(), "getAllNetworks", "()[Landroid/net/Network;");
    if (!getAllNetworksMethod) {
        errlog(g_log, "Failed to get getAllNetworks method");
        return std::nullopt;
    }

    ag::jni::LocalRef<jobjectArray> networks{
            env.get(), static_cast<jobjectArray>(env->CallObjectMethod(connectivityManager, getAllNetworksMethod))};

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        errlog(g_log, "Exception while calling getAllNetworks");
        return std::nullopt;
    }

    if (!networks) {
        errlog(g_log, "Failed to get networks array");
        return std::nullopt;
    }

    jsize networkCount = env->GetArrayLength(networks.get());
    tracelog(g_log, "Found {} networks", networkCount);

    jmethodID getLinkPropertiesMethod =
            env->GetMethodID(cmClass.get(), "getLinkProperties", "(Landroid/net/Network;)Landroid/net/LinkProperties;");
    if (!getLinkPropertiesMethod) {
        errlog(g_log, "Failed to get getLinkProperties method");
        return std::nullopt;
    }

    ag::jni::LocalRef<jobject> network;
    ag::jni::LocalRef<jobject> linkProperties;
    ag::jni::LocalRef<jclass> lpClass;
    ag::jni::LocalRef<jstring> interfaceNameStr;
    ag::jni::LocalRef<jclass> networkClass;

    for (jsize i = 0; i < networkCount; i++) {
        network = ag::jni::LocalRef<jobject>{env.get(), env->GetObjectArrayElement(networks.get(), i)};
        if (!network) {
            continue;
        }

        linkProperties = ag::jni::LocalRef<jobject>{
                env.get(), env->CallObjectMethod(connectivityManager, getLinkPropertiesMethod, network.get())};
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            continue;
        }

        if (!linkProperties) {
            continue;
        }

        lpClass = ag::jni::LocalRef<jclass>{env.get(), env->GetObjectClass(linkProperties.get())};
        if (lpClass) {
            jmethodID getInterfaceNameMethod =
                    env->GetMethodID(lpClass.get(), "getInterfaceName", "()Ljava/lang/String;");
            if (getInterfaceNameMethod) {
                interfaceNameStr = ag::jni::LocalRef<jstring>{env.get(),
                        static_cast<jstring>(env->CallObjectMethod(linkProperties.get(), getInterfaceNameMethod))};
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                    continue;
                }

                if (interfaceNameStr) {
                    const char *interfaceNameChars = env->GetStringUTFChars(interfaceNameStr.get(), nullptr);
                    std::string currentInterfaceName(interfaceNameChars);
                    env->ReleaseStringUTFChars(interfaceNameStr.get(), interfaceNameChars);

                    tracelog(g_log, "Checking network interface: {}", currentInterfaceName);

                    if (currentInterfaceName == interface_name) {
                        networkClass = ag::jni::LocalRef<jclass>{env.get(), env->GetObjectClass(network.get())};
                        if (networkClass) {
                            jmethodID getNetworkHandleMethod =
                                    env->GetMethodID(networkClass.get(), "getNetworkHandle", "()J");
                            if (getNetworkHandleMethod) {
                                jlong networkHandle = env->CallLongMethod(network.get(), getNetworkHandleMethod);
                                if (env->ExceptionCheck()) {
                                    env->ExceptionClear();
                                    continue;
                                }

                                tracelog(g_log, "Found network handle {} for interface '{}'", networkHandle,
                                        interface_name);

                                return static_cast<net_handle_t>(networkHandle);
                            }
                        }
                    }
                }
            }
        }
    }

    tracelog(g_log, "Interface '{}' not found in ConnectivityManager", interface_name);
    return std::nullopt;
}

std::optional<net_handle_t> AndroidContextManager::get_network_handle_for_interface(std::string_view interface_name) {
    if (!g_java_vm) {
        warnlog(g_log, "AndroidContextManager not initialized, unable to resolve interface {}", interface_name);
        return std::nullopt;
    }

    tracelog(g_log, "Getting network handle for interface: {}", interface_name);

    if (g_app_context) {
        auto connectivityManager = get_connectivity_manager();
        if (connectivityManager) {
            auto result = get_network_handle_from_connectivity_manager(connectivityManager, interface_name);

            if (result.has_value()) {
                tracelog(g_log, "Successfully resolved '{}' via ConnectivityManager to handle: {}", interface_name,
                        result.value());
                return result;
            }
        }
    }

    warnlog(g_log, "Unknown interface '{}', no network handle available", interface_name);
    return std::nullopt;
}

void AndroidContextManager::set_multicast_lock_enabled(bool enabled) {
    if (!g_java_vm || !g_app_context) {
        return;
    }

    // Only ever called from the MdnsClient event loop thread.
    if (enabled == static_cast<bool>(g_multicast_lock)) {
        return;
    }

    ag::jni::ScopedJniEnv env(g_java_vm, 16);

    if (!enabled) {
        ag::jni::LocalRef<jclass> lock_class{env.get(), env->GetObjectClass(g_multicast_lock.get())};
        if (lock_class) {
            jmethodID release = env->GetMethodID(lock_class.get(), "release", "()V");
            if (release) {
                env->CallVoidMethod(g_multicast_lock.get(), release);
            }
        }
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        g_multicast_lock = {};
        g_multicast_lock_held.store(false);
        infolog(g_log, "Released WifiManager.MulticastLock for mDNS");
        return;
    }

    auto wifi_manager = get_system_service("wifi");
    if (!wifi_manager) {
        infolog(g_log, "WifiManager is not available, mDNS multicast lock not acquired");
        return;
    }

    ag::jni::LocalRef<jclass> wifi_class{env.get(), env->GetObjectClass(wifi_manager.get())};
    if (!wifi_class) {
        return;
    }
    jmethodID create_lock = env->GetMethodID(wifi_class.get(), "createMulticastLock",
            "(Ljava/lang/String;)Landroid/net/wifi/WifiManager$MulticastLock;");
    if (!create_lock) {
        return;
    }

    ag::jni::LocalRef<jstring> tag{env.get(), env->NewStringUTF("dns-libs-mdns")};
    if (!tag) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        return;
    }

    ag::jni::LocalRef<jobject> lock{env.get(), env->CallObjectMethod(wifi_manager.get(), create_lock, tag.get())};
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return;
    }
    if (!lock) {
        return;
    }

    ag::jni::LocalRef<jclass> lock_class{env.get(), env->GetObjectClass(lock.get())};
    if (!lock_class) {
        return;
    }
    jmethodID set_reference_counted = env->GetMethodID(lock_class.get(), "setReferenceCounted", "(Z)V");
    jmethodID acquire = env->GetMethodID(lock_class.get(), "acquire", "()V");
    if (!set_reference_counted || !acquire) {
        return;
    }

    env->CallVoidMethod(lock.get(), set_reference_counted, JNI_FALSE);
    env->CallVoidMethod(lock.get(), acquire);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return;
    }

    g_multicast_lock = ag::jni::GlobalRef<jobject>(g_java_vm, lock.get());
    g_multicast_lock_held.store(true);
    infolog(g_log, "Acquired WifiManager.MulticastLock for mDNS");
}

bool AndroidContextManager::is_multicast_lock_held() {
    return g_multicast_lock_held.load();
}

net_handle_t AndroidContextManager::get_last_bound_network_handle() {
    return g_last_bound_network_handle.load();
}

void AndroidContextManager::record_bound_network_handle(net_handle_t handle) {
    g_last_bound_network_handle.store(handle);
}

} // namespace ag::dns

#endif // __ANDROID__
