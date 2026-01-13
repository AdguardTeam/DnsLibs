#pragma once

#include <jni.h>
#include <memory>
#include <atomic>

#include "common/defs.h"
#include "dns/proxy/tun_listener.h"
#include "jni_utils.h"

namespace ag::dns {

/**
 * Android JNI wrapper for TunListener.
 * Manages the lifecycle of a C++ TunListener instance and bridges
 * between Java callbacks and C++ callbacks.
 */
class AndroidTunListener {
private:
    TunListener m_listener;
    
    /**
     * Marshal Java callbacks to C++ callbacks.
     */
    TunListener::RequestCallback marshal_request_callback(JNIEnv *env, jobject request_callback);
    
    /**
     * Marshal C++ init result to Java InitResult object.
     */
    jni::LocalRef<jobject> marshal_init_result(JNIEnv *env, const Error<TunListener::InitError> &init_result);
    
    // Sequentially-consistently store after initializing,
    // and sequentially-consistently load BEFORE using,
    // the JNI handles and utils below.
    // Needed for thread-safety if you want to init things in one thread and use them in another.
    std::atomic_bool m_jni_initialized{false};
    
    jni::JniUtils m_utils;
    
    jni::GlobalRef<jobject> m_request_callback{}; // Java RequestCallback
    
    struct {
        jni::GlobalRef<jclass> request_callback_class;
    } m_jclasses{};
    
    struct {
        jmethodID on_request;
    } m_request_callback_methods{};

public:
    /**
     * Constructor - initializes JNI utils.
     * @param vm Java VM instance
     */
    explicit AndroidTunListener(JavaVM *vm);
    
    /**
     * Initialize the TUN listener.
     * @param env JNI environment
     * @param fd File descriptor
     * @param mtu MTU size (0 = use default)
     * @param request_callback Java callback for DNS requests
     * @return InitResult Java object with initialization result
     */
    jobject init(JNIEnv *env, jint fd, jint mtu, jobject request_callback);
    
    /**
     * Deinitialize the TUN listener.
     * @param env JNI environment
     */
    void deinit(JNIEnv *env);
};

} // namespace ag::dns
