#ifdef __ANDROID__

#include "android_context_manager.h"
#include "common/logger.h"
#include <android/multinetwork.h>

#include "scoped_jni_env.h"

namespace ag::dns {

static ag::Logger g_log{"AndroidContextManager"};
static JavaVM *g_java_vm = nullptr;
static ag::jni::GlobalRef<jobject> g_app_context;

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

ag::jni::GlobalRef<jobject> AndroidContextManager::get_connectivity_manager() {
    if (!g_java_vm) {
        errlog(g_log, "AndroidContextManager not initialized");
        return {};
    }

    if (!g_app_context) {
        errlog(g_log, "Application context not set");
        return {};
    }

    ag::jni::ScopedJniEnv env(g_java_vm, 16);

    jobject context = g_app_context.get();

    ag::jni::LocalRef<jclass> contextClass{env.get(), env->GetObjectClass(context)};
    if (!contextClass) {
        errlog(g_log, "Failed to get Context class");
        return {};
    }

    jmethodID getSystemServiceMethod =
            env->GetMethodID(contextClass.get(), "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
    if (!getSystemServiceMethod) {
        errlog(g_log, "Failed to get getSystemService method");
        return {};
    }

    ag::jni::LocalRef<jstring> connectivityServiceStr{env.get(), env->NewStringUTF("connectivity")};
    if (!connectivityServiceStr) {
        errlog(g_log, "Failed to create connectivity service string");
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        return {};
    }

    ag::jni::LocalRef<jobject> connectivityManager{env.get(),
            env->CallObjectMethod(context, getSystemServiceMethod, connectivityServiceStr.get())};

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        errlog(g_log, "Exception while calling getSystemService");
        return {};
    }

    if (!connectivityManager) {
        errlog(g_log, "Failed to get ConnectivityManager");
        return {};
    }

    tracelog(g_log, "Successfully obtained ConnectivityManager");
    return ag::jni::GlobalRef<jobject>(g_java_vm, connectivityManager.get());
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

    ag::jni::LocalRef<jobjectArray> networks{env.get(), static_cast<jobjectArray>(env->CallObjectMethod(connectivityManager, getAllNetworksMethod))};

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

        linkProperties = ag::jni::LocalRef<jobject>{env.get(), env->CallObjectMethod(connectivityManager, getLinkPropertiesMethod, network.get())};
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            continue;
        }

        if (!linkProperties) {
            continue;
        }

        lpClass = ag::jni::LocalRef<jclass>{env.get(), env->GetObjectClass(linkProperties.get())};
        if (lpClass) {
            jmethodID getInterfaceNameMethod = env->GetMethodID(lpClass.get(), "getInterfaceName", "()Ljava/lang/String;");
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

} // namespace ag::dns

#endif // __ANDROID__
