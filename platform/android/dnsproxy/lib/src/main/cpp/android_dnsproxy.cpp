#include <jni.h>
#include <string>
#include <cassert>
#include <dnsproxy.h>
#include <android_dnsproxy.h>
#include <scoped_jni_env.h>
#include <jni_defs.h>
#include <spdlog/sinks/base_sink.h>

class java_sink_mt : public spdlog::sinks::base_sink<std::mutex> {
public:
    static ag::logger create(const std::string &logger_name,
                             JavaVM *vm,
                             ag::global_ref<jclass> &&logger_class) {

        return spdlog::default_factory::template create<java_sink_mt>(
                logger_name, vm, std::move(logger_class));
    }

    java_sink_mt(JavaVM *vm, ag::global_ref<jclass> &&logger_class)
            : m_vm(vm), m_logger_class(std::move(logger_class)) {

        ag::scoped_jni_env env(m_vm, 16);
        m_log_method = env->GetStaticMethodID(m_logger_class.get(), "log", "(ILjava/lang/String;)V");
    }

private:
    JavaVM *m_vm;
    ag::global_ref<jclass> m_logger_class;
    jmethodID m_log_method;

    void sink_it_(const spdlog::details::log_msg &msg) final {
        ag::scoped_jni_env env(m_vm, 16);

        spdlog::memory_buf_t formatted;
        this->formatter_->format(msg, formatted);

        std::string s{formatted.data(), formatted.size()};
        env->CallStaticVoidMethod(m_logger_class.get(), m_log_method, (jint) msg.level, env->NewStringUTF(s.c_str()));

        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            assert(false);
        }
    }

    void flush_() final {}
};

extern "C"
JNIEXPORT jlong JNICALL
Java_com_adguard_dnslibs_proxy_DnsProxy_create(JNIEnv *env, jobject jthis) {
    return (jlong) new ag::android_dnsproxy(env);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_adguard_dnslibs_proxy_DnsProxy_delete(JNIEnv *env, jobject thiz, jlong native_ptr) {
    delete (ag::android_dnsproxy *) native_ptr;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_adguard_dnslibs_proxy_DnsProxy_setLogLevel(JNIEnv *env, jclass clazz, jint level) {
    ag::set_default_log_level((ag::log_level) level);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_adguard_dnslibs_proxy_DnsProxy_init(JNIEnv *env, jobject thiz, jlong native_ptr,
                                             jobject java_settings, jobject java_events) {

    auto vm = ag::get_vm(env);
    ag::global_ref dnsproxy_class(vm, env->FindClass(FQN_DNSPROXY));
    ag::set_logger_factory_callback([vm, dnsproxy_class](const std::string &name) {
        return java_sink_mt::create(name, vm, ag::global_ref(vm, dnsproxy_class.get()));
    });

    auto *proxy = (ag::android_dnsproxy *) native_ptr;
    assert(proxy);
    return (jboolean) proxy->init(env, java_settings, java_events);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_adguard_dnslibs_proxy_DnsProxy_deinit(JNIEnv *env, jobject thiz, jlong native_ptr) {
    auto *proxy = (ag::android_dnsproxy *) native_ptr;
    assert(proxy);
    proxy->deinit(env);
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_adguard_dnslibs_proxy_DnsProxy_getDefaultSettings(JNIEnv *env, jobject thiz, jlong native_ptr) {
    auto *proxy = (ag::android_dnsproxy *) native_ptr;
    assert(proxy);
    return proxy->get_default_settings(env);
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_adguard_dnslibs_proxy_DnsProxy_getSettings(JNIEnv *env, jobject thiz, jlong native_ptr) {
    auto *proxy = (ag::android_dnsproxy *) native_ptr;
    assert(proxy);
    return proxy->get_settings(env);
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_adguard_dnslibs_proxy_DnsProxy_handleMessage(JNIEnv *env, jobject thiz, jlong native_ptr, jbyteArray message) {
    auto *proxy = (ag::android_dnsproxy *) native_ptr;
    assert(proxy);
    return proxy->handle_message(env, message);
}

ag::upstream::options ag::android_dnsproxy::marshal_upstream(JNIEnv *env,
                                                             jobject java_upstream_settings) {

    auto clazz = env->FindClass(FQN_UPSTREAM_SETTINGS);
    assert(env->IsInstanceOf(java_upstream_settings, clazz));

    auto dns_server_field = env->GetFieldID(clazz, "address", "Ljava/lang/String;");
    auto bootstrap_field = env->GetFieldID(clazz, "bootstrap", "Ljava/util/List;");
    auto timeout_field = env->GetFieldID(clazz, "timeoutMs", "J");
    auto server_ip_field = env->GetFieldID(clazz, "serverIp", "[B");

    ag::upstream::options upstream{};

    if (local_ref dns_server{env, env->GetObjectField(java_upstream_settings, dns_server_field)}) {
        m_utils.visit_string(env, dns_server.get(), [&](const char *str, jsize len) {
            upstream.address.assign(str, len); // Copy
        });
    }

    if (local_ref bootstrap{env, env->GetObjectField(java_upstream_settings, bootstrap_field)}) {
        m_utils.iterate(env, bootstrap.get(), [&](local_ref<jobject> &&java_str) {
            m_utils.visit_string(env, java_str.get(), [&](const char *str, jsize len) {
                upstream.bootstrap.emplace_back(str, len); // Copy
            });
        });
    }

    upstream.timeout = std::chrono::milliseconds(env->GetLongField(java_upstream_settings, timeout_field));

    if (local_ref server_ip{env, (jbyteArray) env->GetObjectField(java_upstream_settings, server_ip_field)}) {

        assert(env->IsInstanceOf(server_ip.get(), env->FindClass("[B")));

        auto len = env->GetArrayLength(server_ip.get());

        if (ag::ipv4_address_size == len) {
            ag::ipv4_address_array ipv4{};
            env->GetByteArrayRegion(server_ip.get(), 0, ag::ipv4_address_size, (jbyte *) ipv4.data());
            upstream.resolved_server_ip = ipv4;
        } else if (ag::ipv6_address_size == len) {
            ag::ipv6_address_array ipv6{};
            env->GetByteArrayRegion(server_ip.get(), 0, ag::ipv6_address_size, (jbyte *) ipv6.data());
            upstream.resolved_server_ip = ipv6;
        }
    }

    return upstream;
}

ag::local_ref<jobject> ag::android_dnsproxy::marshal_upstream(JNIEnv *env, const upstream::options &settings) {
    auto clazz = env->FindClass(FQN_UPSTREAM_SETTINGS);
    auto ctor = env->GetMethodID(clazz, "<init>", "()V");
    auto dns_server_field = env->GetFieldID(clazz, "address", "Ljava/lang/String;");
    auto bootstrap_field = env->GetFieldID(clazz, "bootstrap", "Ljava/util/List;");
    auto timeout_field = env->GetFieldID(clazz, "timeoutMs", "J");
    auto server_ip_field = env->GetFieldID(clazz, "serverIp", "[B");

    auto java_upstream = env->NewObject(clazz, ctor);

    env->SetObjectField(java_upstream, dns_server_field, m_utils.marshal_string(env, settings.address).get());
    env->SetLongField(java_upstream, timeout_field, settings.timeout.count());

    if (std::holds_alternative<ag::ipv4_address_array>(settings.resolved_server_ip)) {
        auto ipv4 = std::get<ag::ipv4_address_array>(settings.resolved_server_ip);
        auto arr = env->NewByteArray(ag::ipv4_address_size);
        env->SetByteArrayRegion(arr, 0, ag::ipv4_address_size, (jbyte *) ipv4.data());
        env->SetObjectField(java_upstream, server_ip_field, arr);
    } else if (std::holds_alternative<ag::ipv6_address_array>(settings.resolved_server_ip)) {
        auto ipv6 = std::get<ag::ipv6_address_array>(settings.resolved_server_ip);
        auto arr = env->NewByteArray(ag::ipv6_address_size);
        env->SetByteArrayRegion(arr, 0, ag::ipv6_address_size, (jbyte *) ipv6.data());
        env->SetObjectField(java_upstream, server_ip_field, arr);
    }

    if (local_ref bootstrap{env, env->GetObjectField(java_upstream, bootstrap_field)}) {
        for (auto &bootstrap_address : settings.bootstrap) {
            m_utils.collection_add(env, bootstrap.get(), m_utils.marshal_string(env, bootstrap_address).get());
        }
    }

    return local_ref(env, java_upstream);
}

ag::dns64_settings ag::android_dnsproxy::marshal_dns64(JNIEnv *env, jobject java_dns64_settings) {
    auto clazz = env->FindClass(FQN_DNS64_SETTINGS);
    assert(env->IsInstanceOf(java_dns64_settings, clazz));

    auto upstream_field = env->GetFieldID(clazz, "upstream", "L" FQN_UPSTREAM_SETTINGS ";");
    auto max_tries_field = env->GetFieldID(clazz, "maxTries", "J");
    auto wait_time_field = env->GetFieldID(clazz, "waitTimeMs", "J");

    ag::dns64_settings settings;

    if (auto upstream = env->GetObjectField(java_dns64_settings, upstream_field)) {
        settings.upstream_settings = marshal_upstream(env, upstream);
    }

    settings.max_tries = env->GetLongField(java_dns64_settings, max_tries_field);
    settings.wait_time = std::chrono::milliseconds(env->GetLongField(java_dns64_settings, wait_time_field));

    return settings;
}

ag::local_ref<jobject> ag::android_dnsproxy::marshal_dns64(JNIEnv *env, const ag::dns64_settings &settings) {
    auto clazz = env->FindClass(FQN_DNS64_SETTINGS);
    auto ctor = env->GetMethodID(clazz, "<init>", "()V");
    auto upstream_field = env->GetFieldID(clazz, "upstream", "L" FQN_UPSTREAM_SETTINGS ";");
    auto max_tries_field = env->GetFieldID(clazz, "maxTries", "J");
    auto wait_time_field = env->GetFieldID(clazz, "waitTimeMs", "J");

    auto java_dns64 = env->NewObject(clazz, ctor);

    env->SetLongField(java_dns64, max_tries_field, settings.max_tries);
    env->SetLongField(java_dns64, wait_time_field, settings.wait_time.count());
    env->SetObjectField(java_dns64, upstream_field, marshal_upstream(env, settings.upstream_settings).get());

    return local_ref(env, java_dns64);
}

ag::listener_protocol ag::android_dnsproxy::marshal_protocol(JNIEnv *env, jobject java_protocol) {
    assert(env->IsInstanceOf(java_protocol, env->FindClass(FQN_LISTENER_PROTOCOL)));
    return (ag::listener_protocol) m_utils.get_enum_ordinal(env, java_protocol);
}

ag::local_ref<jobject> ag::android_dnsproxy::marshal_protocol(JNIEnv *env, ag::listener_protocol protocol) {
    return local_ref(env, m_protocol_enum_values.at((size_t) protocol));
}

ag::listener_settings ag::android_dnsproxy::marshal_listener(JNIEnv *env,
                                                             jobject java_listener_settings) {

    auto clazz = env->FindClass(FQN_LISTENER_SETTINGS);
    assert(env->IsInstanceOf(java_listener_settings, clazz));

    auto address_field = env->GetFieldID(clazz, "address", "Ljava/lang/String;");
    auto protocol_field = env->GetFieldID(clazz, "protocol", "L" FQN_LISTENER_PROTOCOL ";");
    auto persistent_field = env->GetFieldID(clazz, "persistent", "Z");
    auto idle_timeout_field = env->GetFieldID(clazz, "idleTimeoutMs", "J");

    ag::listener_settings settings;

    if (local_ref address{env, env->GetObjectField(java_listener_settings, address_field)}) {
        m_utils.visit_string(env, address.get(), [&](const char *str, jsize len) {
            settings.address.assign(str, len);
        });
    }

    settings.port = env->GetIntField(java_listener_settings, env->GetFieldID(clazz, "port", "I"));
    if (auto protocol = env->GetObjectField(java_listener_settings, protocol_field)) {
        settings.protocol = marshal_protocol(env, protocol);
    }

    settings.persistent = env->GetBooleanField(java_listener_settings, persistent_field);
    settings.idle_timeout = std::chrono::milliseconds(env->GetLongField(java_listener_settings, idle_timeout_field));

    return settings;
}

ag::local_ref<jobject> ag::android_dnsproxy::marshal_listener(JNIEnv *env, const ag::listener_settings &settings) {
    auto clazz = env->FindClass(FQN_LISTENER_SETTINGS);
    auto ctor = env->GetMethodID(clazz, "<init>", "()V");
    auto address_field = env->GetFieldID(clazz, "address", "Ljava/lang/String;");
    auto port_field = env->GetFieldID(clazz, "port", "I");
    auto protocol_field = env->GetFieldID(clazz, "protocol", "L" FQN_LISTENER_PROTOCOL ";");
    auto persistent_field = env->GetFieldID(clazz, "persistent", "Z");
    auto idle_timeout_field = env->GetFieldID(clazz, "idleTimeoutMs", "J");

    auto java_listener = env->NewObject(clazz, ctor);

    env->SetObjectField(java_listener, address_field, m_utils.marshal_string(env, settings.address).get());
    env->SetIntField(java_listener, port_field, settings.port);
    env->SetObjectField(java_listener, protocol_field, marshal_protocol(env, settings.protocol).get());
    env->SetBooleanField(java_listener, persistent_field, settings.persistent);
    env->SetLongField(java_listener, idle_timeout_field, settings.idle_timeout.count());

    return local_ref(env, java_listener);
}

ag::dnsfilter::engine_params ag::android_dnsproxy::marshal_filter_params(JNIEnv *env,
                                                                         jobject java_filter_params) {

    auto clazz = env->FindClass("android/util/LongSparseArray");
    assert(env->IsInstanceOf(java_filter_params, clazz));

    auto size_method = env->GetMethodID(clazz, "size", "()I");
    auto key_at_method = env->GetMethodID(clazz, "keyAt", "(I)J");
    auto val_at_method = env->GetMethodID(clazz, "valueAt", "(I)Ljava/lang/Object;");

    ag::dnsfilter::engine_params params;

    jint size = env->CallIntMethod(java_filter_params, size_method);
    for (int64_t i = 0; i < size; ++i) {
        jlong key = env->CallLongMethod(java_filter_params, key_at_method, i);
        local_ref val(env, env->CallObjectMethod(java_filter_params, val_at_method, i));
        m_utils.visit_string(env, val.get(), [&](const char *str, jsize len) {
            params.filters.push_back({.id = (uint32_t) key, .path = std::string(str, len)});
        });
    }

    return params;
}

ag::local_ref<jobject> ag::android_dnsproxy::marshal_filter_params(JNIEnv *env,
                                                                   const ag::dnsfilter::engine_params &params) {

    auto clazz = env->FindClass("android/util/LongSparseArray");
    auto ctor = env->GetMethodID(clazz, "<init>", "()V");
    auto put_method = env->GetMethodID(clazz, "put", "(JLjava/lang/Object;)V");

    auto java_params = env->NewObject(clazz, ctor);

    for (auto &param : params.filters) {
        env->CallVoidMethod(java_params, put_method, (jlong) param.id, m_utils.marshal_string(env, param.path).get());
    }

    return local_ref(env, java_params);
}

ag::dnsproxy_settings ag::android_dnsproxy::marshal_settings(JNIEnv *env,
                                                             jobject java_dnsproxy_settings) {

    auto clazz = env->FindClass(FQN_DNSPROXY_SETTINGS);
    assert(env->IsInstanceOf(java_dnsproxy_settings, clazz));

    auto blocked_response_ttl_field = env->GetFieldID(clazz, "blockedResponseTtlSecs", "J");
    auto dns64_field = env->GetFieldID(clazz, "dns64", "L" FQN_DNS64_SETTINGS ";");
    auto upstreams_field = env->GetFieldID(clazz, "upstreams", "Ljava/util/List;");
    auto listeners_field = env->GetFieldID(clazz, "listeners", "Ljava/util/List;");
    auto filter_params_field = env->GetFieldID(clazz, "filterParams", "Landroid/util/LongSparseArray;");
    auto ipv6_avail_field = env->GetFieldID(clazz, "ipv6Available", "Z");
    auto block_ipv6_field = env->GetFieldID(clazz, "blockIpv6", "Z");

    ag::dnsproxy_settings settings{};

    settings.blocked_response_ttl_secs = env->GetLongField(java_dnsproxy_settings, blocked_response_ttl_field);

    if (local_ref upstreams{env, env->GetObjectField(java_dnsproxy_settings, upstreams_field)}) {
        m_utils.iterate(env, upstreams.get(), [&](local_ref<jobject> &&java_upstream_settings) {
            settings.upstreams.push_back(marshal_upstream(env, java_upstream_settings.get()));
        });
    }

    if (local_ref listeners{env, env->GetObjectField(java_dnsproxy_settings, listeners_field)}) {
        m_utils.iterate(env, listeners.get(), [&](local_ref<jobject> &&java_listener_settings) {
            settings.listeners.push_back(marshal_listener(env, java_listener_settings.get()));
        });
    }

    if (auto dns64_settings = env->GetObjectField(java_dnsproxy_settings, dns64_field)) {
        settings.dns64 = marshal_dns64(env, dns64_settings);
    }

    if (auto filter_params = env->GetObjectField(java_dnsproxy_settings, filter_params_field)) {
        settings.filter_params = marshal_filter_params(env, filter_params);
    }

    settings.ipv6_available = env->GetBooleanField(java_dnsproxy_settings, ipv6_avail_field);
    settings.block_ipv6 = env->GetBooleanField(java_dnsproxy_settings, block_ipv6_field);

    return settings;
}

ag::local_ref<jobject> ag::android_dnsproxy::marshal_settings(JNIEnv *env, const ag::dnsproxy_settings &settings) {
    auto clazz = env->FindClass(FQN_DNSPROXY_SETTINGS);
    auto ctor = env->GetMethodID(clazz, "<init>", "()V");

    auto blocked_response_ttl_field = env->GetFieldID(clazz, "blockedResponseTtlSecs", "J");
    auto dns64_field = env->GetFieldID(clazz, "dns64", "L" FQN_DNS64_SETTINGS ";");
    auto upstreams_field = env->GetFieldID(clazz, "upstreams", "Ljava/util/List;");
    auto listeners_field = env->GetFieldID(clazz, "listeners", "Ljava/util/List;");
    auto filter_params_field = env->GetFieldID(clazz, "filterParams", "Landroid/util/LongSparseArray;");
    auto ipv6_avail_field = env->GetFieldID(clazz, "ipv6Available", "Z");
    auto block_ipv6_field = env->GetFieldID(clazz, "blockIpv6", "Z");

    auto java_settings = env->NewObject(clazz, ctor);

    env->SetLongField(java_settings, blocked_response_ttl_field, settings.blocked_response_ttl_secs);

    if (settings.dns64.has_value()) {
        env->SetObjectField(java_settings, dns64_field, marshal_dns64(env, settings.dns64.value()).get());
    }

    if (local_ref upstreams{env, env->GetObjectField(java_settings, upstreams_field)}) {
        for (auto &upstream : settings.upstreams) {
            m_utils.collection_add(env, upstreams.get(), marshal_upstream(env, upstream).get());
        }
    }

    if (local_ref listeners{env, env->GetObjectField(java_settings, listeners_field)}) {
        for (auto &listener : settings.listeners) {
            m_utils.collection_add(env, listeners.get(), marshal_listener(env, listener).get());
        }
    }

    env->SetObjectField(java_settings, filter_params_field, marshal_filter_params(env, settings.filter_params).get());
    env->SetBooleanField(java_settings, ipv6_avail_field, (jboolean) settings.ipv6_available);
    env->SetBooleanField(java_settings, block_ipv6_field, (jboolean) settings.block_ipv6);

    return local_ref(env, java_settings);
}

ag::local_ref<jobject> ag::android_dnsproxy::marshal_processed_event(JNIEnv *env,
                                                                     const ag::dns_request_processed_event &event) {

    auto check = m_jni_initialized.load();
    assert(check);

    auto java_event = env->NewObject(m_jclasses.processed_event.get(), m_processed_event_methods.ctor);

    env->SetObjectField(java_event, m_processed_event_fields.domain, m_utils.marshal_string(env, event.domain).get());
    env->SetObjectField(java_event, m_processed_event_fields.type, m_utils.marshal_string(env, event.type).get());
    env->SetObjectField(java_event, m_processed_event_fields.answer, m_utils.marshal_string(env, event.answer).get());
    env->SetObjectField(java_event, m_processed_event_fields.error, m_utils.marshal_string(env, event.error).get());
    env->SetObjectField(java_event, m_processed_event_fields.upstream_addr,
                        m_utils.marshal_string(env, event.upstream_addr).get());
    env->SetLongField(java_event, m_processed_event_fields.start_time, event.start_time);
    env->SetIntField(java_event, m_processed_event_fields.elapsed, event.elapsed);
    env->SetIntField(java_event, m_processed_event_fields.bytes_sent, event.bytes_sent);
    env->SetIntField(java_event, m_processed_event_fields.bytes_received, event.bytes_received);
    env->SetBooleanField(java_event, m_processed_event_fields.whitelist, event.whitelist);

    {
        const jsize ids_len = event.filter_list_ids.size();
        local_ref ids(env, env->NewIntArray(ids_len));
        for (int64_t i = 0; i < ids_len; ++i) {
            jint e = event.filter_list_ids[i];
            env->SetIntArrayRegion(ids.get(), i, 1, &e);
        }
        env->SetObjectField(java_event, m_processed_event_fields.filter_list_ids, ids.get());
    }

    if (local_ref rules{env, env->GetObjectField(java_event, m_processed_event_fields.rules)}) {
        for (auto &rule : event.rules) {
            m_utils.collection_add(env, rules.get(), m_utils.marshal_string(env, rule).get());
        }
    }

    return local_ref(env, java_event);
}

ag::local_ref<jobject> ag::android_dnsproxy::marshal_certificate_verification_event(
        JNIEnv *env, const ag::certificate_verification_event &event) {
    auto check = m_jni_initialized.load();
    assert(check);

    auto java_event = env->NewObject(m_jclasses.cert_verify_event.get(), m_cert_verify_event_methods.ctor);

    env->SetObjectField(java_event,
                        m_cert_verify_event_fields.certificate,
                        m_utils.marshal_uint8_view(env, {event.certificate.data(), event.certificate.size()}).get());

    if (local_ref chain{env, env->GetObjectField(java_event, m_cert_verify_event_fields.chain)}) {
        for (auto &cert : event.chain) {
            m_utils.collection_add(env, chain.get(), m_utils.marshal_uint8_view(env, {cert.data(), cert.size()}).get());
        }
    }

    return ag::local_ref(env, java_event);
}

ag::dnsproxy_events ag::android_dnsproxy::marshal_events(JNIEnv *env, jobject java_events) {
    if (!java_events) {
        return {};
    }

    auto vm = get_vm(env);
    assert(vm);

    ag::dnsproxy_events events;

    events.on_request_processed = [this, vm](const ag::dns_request_processed_event &event) {
        scoped_jni_env scoped_env(vm, 16);

        auto java_event = marshal_processed_event(scoped_env.get(), event);
        scoped_env->CallVoidMethod(m_events.get(), m_events_interface_methods.on_request_processed, java_event.get());

        if (scoped_env->ExceptionCheck()) {
            scoped_env->ExceptionClear();
            assert(false);
        }
    };

    events.on_certificate_verification = [this, vm](const ag::certificate_verification_event &event) {
        scoped_jni_env scoped_env(vm, 16);

        auto java_event = marshal_certificate_verification_event(scoped_env.get(), event);
        std::optional<std::string> result = std::nullopt;

        auto response = scoped_env->CallObjectMethod(
                m_events.get(), m_events_interface_methods.on_certificate_verification, java_event.get());

        if (scoped_env->ExceptionCheck()) {
            scoped_env->ExceptionClear();
            assert(false);
        }

        if (response) {
            m_utils.visit_string(scoped_env.get(), response, [&result](const char *str, jint len) {
                result = std::string(str, len);
            });
        }

        return result;
    };

    return events;
}

bool ag::android_dnsproxy::init(JNIEnv *env, jobject settings, jobject events) {
    auto check = m_jni_initialized.load();
    assert(check);

    m_events = global_ref(get_vm(env), events);

    auto cpp_settings = marshal_settings(env, settings);
    auto cpp_events = marshal_events(env, events);

    return m_actual_proxy.init(cpp_settings, cpp_events);
}

void ag::android_dnsproxy::deinit(JNIEnv *env) {
    auto check = m_jni_initialized.load();
    assert(check);
    m_actual_proxy.deinit();
}

jbyteArray ag::android_dnsproxy::handle_message(JNIEnv *env, jbyteArray message) {
    auto elements = env->GetByteArrayElements(message, nullptr); // May copy, must call ReleaseByteArrayElements
    auto size = env->GetArrayLength(message);

    auto result = m_actual_proxy.handle_message({(uint8_t *) elements, (size_t) size});

    // Free the buffer without copying back the possible changes
    env->ReleaseByteArrayElements(message, elements, JNI_ABORT);

    auto result_array = env->NewByteArray(result.size());
    env->SetByteArrayRegion(result_array, 0, result.size(), (jbyte *) result.data());

    return result_array;
}

jobject ag::android_dnsproxy::get_default_settings(JNIEnv *env) {
    auto check = m_jni_initialized.load();
    assert(check);
    return env->NewLocalRef(marshal_settings(env, ag::dnsproxy_settings::get_default()).get());
}

jobject ag::android_dnsproxy::get_settings(JNIEnv *env) {
    auto check = m_jni_initialized.load();
    assert(check);
    return env->NewLocalRef(marshal_settings(env, m_actual_proxy.get_settings()).get());
}

ag::android_dnsproxy::android_dnsproxy(JNIEnv *env) : m_utils(env) {
    auto vm = get_vm(env);

    jclass c = (m_jclasses.processed_event = global_ref(vm, env->FindClass(FQN_REQ_PROC_EVENT))).get();
    m_processed_event_methods.ctor = env->GetMethodID(c, "<init>", "()V");
    m_processed_event_fields.error = env->GetFieldID(c, "error", "Ljava/lang/String;");
    m_processed_event_fields.answer = env->GetFieldID(c, "answer", "Ljava/lang/String;");
    m_processed_event_fields.upstream_addr = env->GetFieldID(c, "upstreamAddr", "Ljava/lang/String;");
    m_processed_event_fields.domain = env->GetFieldID(c, "domain", "Ljava/lang/String;");
    m_processed_event_fields.type = env->GetFieldID(c, "type", "Ljava/lang/String;");
    m_processed_event_fields.bytes_received = env->GetFieldID(c, "bytesReceived", "I");
    m_processed_event_fields.bytes_sent = env->GetFieldID(c, "bytesSent", "I");
    m_processed_event_fields.elapsed = env->GetFieldID(c, "elapsed", "I");
    m_processed_event_fields.start_time = env->GetFieldID(c, "startTime", "J");
    m_processed_event_fields.whitelist = env->GetFieldID(c, "whitelist", "Z");
    m_processed_event_fields.rules = env->GetFieldID(c, "rules", "Ljava/util/List;");
    m_processed_event_fields.filter_list_ids = env->GetFieldID(c, "filterListIds", "[I");

    c = (m_jclasses.cert_verify_event = global_ref(vm, env->FindClass(FQN_CERT_VERIFY_EVENT))).get();
    m_cert_verify_event_methods.ctor = env->GetMethodID(c, "<init>", "()V");
    m_cert_verify_event_fields.certificate = env->GetFieldID(c, "certificate", "[B");
    m_cert_verify_event_fields.chain = env->GetFieldID(c, "chain", "Ljava/util/List;");

    c = (m_jclasses.events_interface = global_ref(vm, env->FindClass(FQN_DNSPROXY_EVENTS))).get();
    m_events_interface_methods.on_request_processed = env->GetMethodID(
            c, "onRequestProcessed", "(L" FQN_REQ_PROC_EVENT ";)V");
    m_events_interface_methods.on_certificate_verification = env->GetMethodID(
            c, "onCertificateVerification", "(L" FQN_CERT_VERIFY_EVENT ";)Ljava/lang/String;");

    m_protocol_enum_values = m_utils.get_enum_values(env, FQN_LISTENER_PROTOCOL);

    m_jni_initialized.store(true);
}
