#pragma once

#include <jni.h>

#include "common/defs.h"
#include "dns/dnsstamp/dns_stamp.h"
#include "dns/proxy/dnsproxy.h"

#include "jni_utils.h"

namespace ag::dns {

class AndroidDnsProxy {
private:
    DnsProxy m_actual_proxy;
    // Sequentially-consistently store after initializing,
    // and sequentially-consistently load BEFORE using,
    // the JNI handles and utils below.
    // Needed for thread-safety if you want to init things in one thread and use them in another.
    std::atomic_bool m_jni_initialized{false};

    jni::JniUtils m_utils;

    jni::GlobalRef<jobject> m_events{}; // Java events interface

    struct {
        jni::GlobalRef<jclass> events_interface;
        jni::GlobalRef<jclass> processed_event;
        jni::GlobalRef<jclass> cert_verify_event;
        jni::GlobalRef<jclass> filtering_log_action;
        jni::GlobalRef<jclass> rule_template;
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
    } m_filtering_log_action_methods;

    struct {
        jfieldID text;
    } m_rule_template_fields;

    struct {
        jmethodID ctor;
    } m_rule_template_methods;

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

    std::vector<jni::GlobalRef<jobject>> m_listener_protocol_enum_values;
    std::vector<jni::GlobalRef<jobject>> m_proxy_protocol_enum_values;
    std::vector<jni::GlobalRef<jobject>> m_blocking_mode_values;
    std::vector<jni::GlobalRef<jobject>> m_dnsproxy_init_result;

    /**
     * Marshal upstream settings from Java to C++.
     */
    UpstreamOptions marshal_upstream(JNIEnv *env, jobject java_upstream_settings);

    /**
     * Marshal upstream settings from C++ to Java.
     */
    jni::LocalRef<jobject> marshal_upstream(JNIEnv *env, const UpstreamOptions &settings);

    /**
     * Marshal DNS64 settings from Java to C++;
     */
    Dns64Settings marshal_dns64(JNIEnv *env, jobject java_dns64_settings);

    /**
     * Marshal DNS64 settings from C++ to Java.
     */
    jni::LocalRef<jobject> marshal_dns64(JNIEnv *env, const Dns64Settings &settings);

    /**
     * Marshal settings overrides from Java to C++.
     */
    ProxySettingsOverrides marshal_settings_overrides(JNIEnv *env, jobject x);

    /**
     * Marshal settings overrides settings from C++ to Java.
     */
    jni::LocalRef<jobject> marshal_settings_overrides(JNIEnv *env, const ProxySettingsOverrides &x);

    /**
     * Marshal listener settings from Java to C++.
     */
    ListenerSettings marshal_listener(JNIEnv *env, jobject java_listener_settings);

    /**
     * Marshal listener settings from C++ to Java.
     */
    jni::LocalRef<jobject> marshal_listener(JNIEnv *env, const ListenerSettings &settings);

    /**
     * Marshal DNS64 settings from Java to C++;
     */
    OutboundProxySettings marshal_outbound_proxy(JNIEnv *env, jobject jsettings);

    /**
     * Marshal DNS64 settings from C++ to Java.
     */
    jni::LocalRef<jobject> marshal_outbound_proxy(JNIEnv *env, const OutboundProxySettings &csettings);

    /**
     * Marshal filter parameters from Java to C++.
     */
    DnsFilter::EngineParams marshal_filter_params(JNIEnv *env, jobject java_filter_params);

    /**
     * Marshal filter parameters from C++ to Java.
     */
    jni::LocalRef<jobject> marshal_filter_params(JNIEnv *env, const DnsFilter::FilterParams &params);

    /**
     * Marshal DNS proxy settings from Java to C++.
     */
    DnsProxySettings marshal_settings(JNIEnv *env, jobject java_dnsproxy_settings);

    /**
     * Marshal DNS proxy settings from C++ to Java.
     */
    jni::LocalRef<jobject> marshal_settings(JNIEnv *env, const DnsProxySettings &settings);

    /**
     * Marshal a "DNS request processed" event from C++ to Java.
     */
    jni::LocalRef<jobject> marshal_processed_event(JNIEnv *env, const DnsRequestProcessedEvent &event);

    /**
     * Marshal a "DNS request processed" event from Java to C++.
     */
    DnsRequestProcessedEvent marshal_processed_event(JNIEnv *env, jobject event);

    /**
     * Marshal a "Certificate verification" event from C++ to Java.
     */
    jni::LocalRef<jobject> marshal_certificate_verification_event(JNIEnv *env, const CertificateVerificationEvent &event);

    /**
     * Marshal Java events interface to C++ dnsproxy_events struct.
     */
    DnsProxyEvents marshal_events(JNIEnv *env, jobject java_events);

    /**
     * Marshal DnsProxyInitResult from C++ to Java.
     */
    jni::LocalRef<jobject> marshal_init_result(JNIEnv *env, const DnsProxy::DnsProxyInitResult &init_result);

    /**
     * Marshal a filtering log action from C++ to Java.
     */
    jni::LocalRef<jobject> marshal_filtering_log_action(JNIEnv *env, const DnsFilter::FilteringLogAction &action);

    /**
     * Marshal a rule template from C++ to Java.
     */
    jni::LocalRef<jobject> marshal_rule_template(JNIEnv *env, const DnsFilter::RuleTemplate &tmplt);

    /**
     * Marshal a rule template from Java to C++.
     */
    DnsFilter::RuleTemplate marshal_rule_template(JNIEnv *env, jobject tmplt);

public:

    /**
     * Initializes global refs.
     */
    explicit AndroidDnsProxy(JavaVM *vm);

    /**
     * Initialize the actual proxy.
     * @param settings Proxy settings from Java.
     * @param events   Proxy events interface from Java.
     * @return Whether initialization was successful.
     */
    jobject init(JNIEnv *env, jobject settings, jobject events);

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
     * @return Null or error string marshalled to Java.
     */
    jstring test_upstream(JNIEnv *env, jobject upstream_settings, jint timeout_ms, jboolean ipv6, jobject events_adapter, jboolean offline);

    /**
     * Suggest an action for filtering log event.
     * @return Action or null on error.
     */
    jobject filtering_log_action_from_event(JNIEnv *env, jobject event);

    /**
     * Generate a rule from a template (obtained from a filtering log action) and a corresponding event.
     * @return Rule or null on error.
     */
    jstring generate_rule(JNIEnv *env, jobject tmplt, jobject event, jint options);
};

}
