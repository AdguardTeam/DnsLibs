#pragma once

#include <jni.h>
#include <ag_defs.h>
#include <jni_utils.h>
#include <dns_stamp.h>

namespace ag {

class android_dnsproxy {
private:
    dnsproxy m_actual_proxy;
    // Sequentially-consistently store after initializing,
    // and sequentially-consistently load BEFORE using,
    // the JNI handles and utils below.
    // Needed for thread-safety if you want to init things in one thread and use them in another.
    std::atomic_bool m_jni_initialized{false};

    jni_utils m_utils;

    global_ref<jobject> m_events{}; // Java events interface

    struct {
        global_ref<jclass> events_interface;
        global_ref<jclass> processed_event;
        global_ref<jclass> cert_verify_event;
    } m_jclasses{};

    struct {
        jmethodID on_request_processed;
        jmethodID on_certificate_verification;
    } m_events_interface_methods{};

    struct {
        jfieldID domain;
        jfieldID type;
        jfieldID start_time;
        jfieldID elapsed;
        jfieldID status;
        jfieldID answer;
        jfieldID original_answer;
        jfieldID upstream_id;
        jfieldID bytes_sent;
        jfieldID bytes_received;
        jfieldID rules;
        jfieldID filter_list_ids;
        jfieldID whitelist;
        jfieldID error;
        jfieldID cache_hit;
        jfieldID dnssec;
    } m_processed_event_fields{};

    struct {
        jmethodID ctor;
    } m_processed_event_methods{};

    struct {
        jfieldID certificate;
        jfieldID chain;
    } m_cert_verify_event_fields{};

    struct {
        jmethodID ctor;
    } m_cert_verify_event_methods{};

    std::vector<global_ref<jobject>> m_listener_protocol_enum_values;
    std::vector<global_ref<jobject>> m_proxy_protocol_enum_values;
    std::vector<global_ref<jobject>> m_blocking_mode_values;

    /**
     * Marshal upstream settings from Java to C++.
     */
    upstream_options marshal_upstream(JNIEnv *env, jobject java_upstream_settings);

    /**
     * Marshal upstream settings from C++ to Java.
     */
    local_ref<jobject> marshal_upstream(JNIEnv *env, const upstream_options &settings);

    /**
     * Marshal DNS64 settings from Java to C++;
     */
    dns64_settings marshal_dns64(JNIEnv *env, jobject java_dns64_settings);

    /**
     * Marshal DNS64 settings from C++ to Java.
     */
    local_ref<jobject> marshal_dns64(JNIEnv *env, const dns64_settings &settings);

    /**
     * Marshal listener settings from Java to C++.
     */
    listener_settings marshal_listener(JNIEnv *env, jobject java_listener_settings);

    /**
     * Marshal listener settings from C++ to Java.
     */
    local_ref<jobject> marshal_listener(JNIEnv *env, const listener_settings &settings);

    /**
     * Marshal DNS64 settings from Java to C++;
     */
    outbound_proxy_settings marshal_outbound_proxy(JNIEnv *env, jobject jsettings);

    /**
     * Marshal DNS64 settings from C++ to Java.
     */
    local_ref<jobject> marshal_outbound_proxy(JNIEnv *env, const outbound_proxy_settings &csettings);

    /**
     * Marshal filter parameters from Java to C++.
     */
    dnsfilter::engine_params marshal_filter_params(JNIEnv *env, jobject java_filter_params);

    /**
     * Marshal filter parameters from C++ to Java.
     */
    local_ref<jobject> marshal_filter_params(JNIEnv *env, const dnsfilter::filter_params &params);

    /**
     * Marshal DNS proxy settings from Java to C++.
     */
    dnsproxy_settings marshal_settings(JNIEnv *env, jobject java_dnsproxy_settings);

    /**
     * Marshal DNS proxy settings from C++ to Java.
     */
    local_ref<jobject> marshal_settings(JNIEnv *env, const dnsproxy_settings &settings);

    /**
     * Marshal a "DNS request processed" event from C++ to Java.
     */
    local_ref<jobject> marshal_processed_event(JNIEnv *env, const dns_request_processed_event &event);

    /**
     * Marshal a "Certificate verification" event from C++ to Java.
     */
    local_ref<jobject> marshal_certificate_verification_event(JNIEnv *env, const certificate_verification_event &event);

    /**
     * Marshal Java events interface to C++ dnsproxy_events struct.
     */
    dnsproxy_events marshal_events(JNIEnv *env, jobject java_events);

public:

    /**
     * Initializes global refs.
     */
    explicit android_dnsproxy(JavaVM *vm);

    /**
     * Initialize the actual proxy.
     * @param settings Proxy settings from Java.
     * @param events   Proxy events interface from Java.
     * @return Whether initialization was successful.
     */
    bool init(JNIEnv *env, jobject settings, jobject events);

    /**
     * Deinit the actual proxy and release all resources held by this object.
     * MUST be called before deleting this object.
     */
    void deinit(JNIEnv *env);

    /**
     * Process a DNS request.
     * @param message The DNS request, from Java.
     * @return The response, marshalled to Java.
     */
    jbyteArray handle_message(JNIEnv *env, jbyteArray message);

    /**
     * @return The default proxy settings, marshalled to Java.
     */
    jobject get_default_settings(JNIEnv *env);

    /**
     * @return The current proxy settings, marshalled to Java.
     */
    jobject get_settings(JNIEnv *env);

    /**
     * Checks if upstream is valid and available.
     * @return Null or error string marshaleed to Java.
     */
    jstring test_upstream(JNIEnv *env, jobject upstream_settings, jobject events_adapter);
};

}
