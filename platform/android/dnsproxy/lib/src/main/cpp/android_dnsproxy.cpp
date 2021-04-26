#include <jni.h>
#include <string>
#include <cassert>
#include <cctype>
#include <dnsproxy.h>
#include <android_dnsproxy.h>
#include <scoped_jni_env.h>
#include <jni_defs.h>
#include <spdlog/sinks/base_sink.h>
#include <upstream_utils.h>

class java_sink_mt : public spdlog::sinks::base_sink<std::mutex> {
public:
    static ag::logger create(const std::string &logger_name,
                             JavaVM *vm,
                             ag::global_ref<jclass> logger_class) {

        return spdlog::default_factory::create<java_sink_mt>(logger_name, vm, std::move(logger_class));
    }

    java_sink_mt(JavaVM *vm, ag::global_ref<jclass> logger_class)
            : m_vm{vm}, m_logger_class{std::move(logger_class)} {

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
        while (!s.empty() && std::isspace((unsigned char) s.back())) {
            s.pop_back();
        }
        env->CallStaticVoidMethod(m_logger_class.get(), m_log_method,
                                  (jint) msg.level, ag::jni_utils::marshal_string(env.get(), s).get());

        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            assert(false);
        }
    }

    void flush_() final {}
};

extern "C"
JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *) {
    ag::scoped_jni_env env(vm, 1);
    ag::global_ref dnsproxy_class(vm, env->FindClass(FQN_DNSPROXY));
    ag::set_logger_factory_callback([vm, dnsproxy_class](const std::string &name) {
        return java_sink_mt::create(name, vm, dnsproxy_class);
    });
    return JNI_VERSION_1_2;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_adguard_dnslibs_proxy_DnsProxy_create(JNIEnv *env, jobject jthis) {
    return (jlong) new ag::android_dnsproxy(ag::get_vm(env));
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
Java_com_adguard_dnslibs_proxy_DnsProxy_isValidRule(JNIEnv *env, jclass clazz, jstring str) {
    bool result = false;

    ag::jni_utils::visit_string(env, str,
        [&result] (const char *str, jsize len) {
            result = ag::dnsfilter::is_valid_rule({ str, (size_t)len });
        });

    return result;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_adguard_dnslibs_proxy_DnsProxy_testUpstreamNative(JNIEnv *env, jclass clazz, jlong native_ptr,
                                                           jobject upstream_settings, jobject events_adapter) {
    auto *proxy = (ag::android_dnsproxy *) native_ptr;
    return proxy->test_upstream(env, upstream_settings, events_adapter);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_adguard_dnslibs_proxy_DnsProxy_init(JNIEnv *env, jobject thiz, jlong native_ptr,
                                             jobject java_settings, jobject java_events) {

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

ag::upstream_options ag::android_dnsproxy::marshal_upstream(JNIEnv *env,
                                                             jobject java_upstream_settings) {

    auto clazz = env->FindClass(FQN_UPSTREAM_SETTINGS);
    assert(env->IsInstanceOf(java_upstream_settings, clazz));

    auto dns_server_field = env->GetFieldID(clazz, "address", "Ljava/lang/String;");
    auto bootstrap_field = env->GetFieldID(clazz, "bootstrap", "Ljava/util/List;");
    auto timeout_field = env->GetFieldID(clazz, "timeoutMs", "J");
    auto server_ip_field = env->GetFieldID(clazz, "serverIp", "[B");
    auto id_field = env->GetFieldID(clazz, "id", "I");
    auto if_field = env->GetFieldID(clazz, "outboundInterfaceName", "Ljava/lang/String;");

    ag::upstream_options upstream{};
    upstream.id = env->GetIntField(java_upstream_settings, id_field);

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

    if (local_ref if_name{env, (jstring) env->GetObjectField(java_upstream_settings, if_field)}) {
        upstream.outbound_interface = m_utils.marshal_string(env, if_name.get());
    }

    return upstream;
}

ag::local_ref<jobject> ag::android_dnsproxy::marshal_upstream(JNIEnv *env, const upstream_options &settings) {
    auto clazz = env->FindClass(FQN_UPSTREAM_SETTINGS);
    auto ctor = env->GetMethodID(clazz, "<init>", "()V");
    auto dns_server_field = env->GetFieldID(clazz, "address", "Ljava/lang/String;");
    auto bootstrap_field = env->GetFieldID(clazz, "bootstrap", "Ljava/util/List;");
    auto timeout_field = env->GetFieldID(clazz, "timeoutMs", "J");
    auto server_ip_field = env->GetFieldID(clazz, "serverIp", "[B");
    auto id_field = env->GetFieldID(clazz, "id", "I");
    auto if_field = env->GetFieldID(clazz, "outboundInterfaceName", "Ljava/lang/String;");

    auto java_upstream = env->NewObject(clazz, ctor);

    env->SetObjectField(java_upstream, dns_server_field, m_utils.marshal_string(env, settings.address).get());
    env->SetLongField(java_upstream, timeout_field, settings.timeout.count());
    env->SetIntField(java_upstream, id_field, settings.id);

    if (std::holds_alternative<ag::ipv4_address_array>(settings.resolved_server_ip)) {
        auto ipv4 = std::get<ag::ipv4_address_array>(settings.resolved_server_ip);
        env->SetObjectField(java_upstream, server_ip_field, m_utils.marshal_uint8_view(env, { ipv4.data(), ag::ipv4_address_size }).get());
    } else if (std::holds_alternative<ag::ipv6_address_array>(settings.resolved_server_ip)) {
        auto ipv6 = std::get<ag::ipv6_address_array>(settings.resolved_server_ip);
        env->SetObjectField(java_upstream, server_ip_field, m_utils.marshal_uint8_view(env, { ipv6.data(), ag::ipv6_address_size }).get());
    }

    if (local_ref bootstrap{env, env->GetObjectField(java_upstream, bootstrap_field)}) {
        for (auto &bootstrap_address : settings.bootstrap) {
            m_utils.collection_add(env, bootstrap.get(), m_utils.marshal_string(env, bootstrap_address).get());
        }
    }

    if (const std::string *name = std::get_if<std::string>(&settings.outbound_interface)) {
        env->SetObjectField(java_upstream, if_field, m_utils.marshal_string(env, *name).get());
    }

    return local_ref(env, java_upstream);
}

ag::dns64_settings ag::android_dnsproxy::marshal_dns64(JNIEnv *env, jobject java_dns64_settings) {
    auto clazz = env->FindClass(FQN_DNS64_SETTINGS);
    assert(env->IsInstanceOf(java_dns64_settings, clazz));

    auto upstreams_field = env->GetFieldID(clazz, "upstreams", "Ljava/util/List;");
    auto max_tries_field = env->GetFieldID(clazz, "maxTries", "J");
    auto wait_time_field = env->GetFieldID(clazz, "waitTimeMs", "J");

    ag::dns64_settings settings;

    if (auto upstreams = env->GetObjectField(java_dns64_settings, upstreams_field)) {
        m_utils.iterate(env, upstreams, [&](local_ref<jobject> upstream) {
            settings.upstreams.push_back(marshal_upstream(env, upstream.get()));
        });
    }

    settings.max_tries = env->GetLongField(java_dns64_settings, max_tries_field);
    settings.wait_time = std::chrono::milliseconds(env->GetLongField(java_dns64_settings, wait_time_field));

    return settings;
}

ag::local_ref<jobject> ag::android_dnsproxy::marshal_dns64(JNIEnv *env, const ag::dns64_settings &settings) {
    auto clazz = env->FindClass(FQN_DNS64_SETTINGS);
    auto ctor = env->GetMethodID(clazz, "<init>", "()V");
    auto upstreams_field = env->GetFieldID(clazz, "upstreams", "Ljava/util/List;");
    auto max_tries_field = env->GetFieldID(clazz, "maxTries", "J");
    auto wait_time_field = env->GetFieldID(clazz, "waitTimeMs", "J");

    auto java_dns64 = env->NewObject(clazz, ctor);

    env->SetLongField(java_dns64, max_tries_field, settings.max_tries);
    env->SetLongField(java_dns64, wait_time_field, settings.wait_time.count());

    if (auto upstreams = env->GetObjectField(java_dns64, upstreams_field)) {
        for (auto &us : settings.upstreams) {
            m_utils.collection_add(env, upstreams, marshal_upstream(env, us).get());
        }
    }

    return local_ref(env, java_dns64);
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
        settings.protocol = (ag::listener_protocol) m_utils.get_enum_ordinal(env, protocol);
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
    env->SetObjectField(java_listener, protocol_field, m_protocol_enum_values.at((size_t) settings.protocol).get());
    env->SetBooleanField(java_listener, persistent_field, settings.persistent);
    env->SetLongField(java_listener, idle_timeout_field, settings.idle_timeout.count());

    return local_ref(env, java_listener);
}

ag::dnsfilter::engine_params ag::android_dnsproxy::marshal_filter_params(JNIEnv *env,
                                                                         jobject java_filter_params) {

    auto clazz = env->FindClass(FQN_FILTER_PARAMS);
    assert(env->IsInstanceOf(java_filter_params, clazz));

    auto id_field = env->GetFieldID(clazz, "id", "I");
    auto data_field = env->GetFieldID(clazz, "data", "Ljava/lang/String;");
    auto in_memory_field = env->GetFieldID(clazz, "inMemory", "Z");

    ag::dnsfilter::engine_params params{};

    m_utils.iterate(env, java_filter_params, [&](local_ref<jobject> jfp) {
        ag::dnsfilter::filter_params fp{};
        fp.id = env->GetIntField(jfp.get(), id_field);
        if (jstring jdata = (jstring) env->GetObjectField(jfp.get(), data_field);
                !env->IsSameObject(nullptr, jdata)) {
            fp.data = m_utils.marshal_string(env, jdata);
        }
        fp.in_memory = env->GetBooleanField(jfp.get(), in_memory_field);
        params.filters.emplace_back(std::move(fp));
    });

    return params;
}

ag::local_ref<jobject> ag::android_dnsproxy::marshal_filter_params(JNIEnv *env,
                                                                   const dnsfilter::filter_params &params) {

    auto clazz = env->FindClass(FQN_FILTER_PARAMS);
    auto ctor = env->GetMethodID(clazz, "<init>", "()V");
    auto id_field = env->GetFieldID(clazz, "id", "I");
    auto data_field = env->GetFieldID(clazz, "data", "Ljava/lang/String;");
    auto in_memory_field = env->GetFieldID(clazz, "inMemory", "Z");

    auto java_params = env->NewObject(clazz, ctor);

    env->SetIntField(java_params, id_field, params.id);
    env->SetObjectField(java_params, data_field, m_utils.marshal_string(env, params.data).get());
    env->SetBooleanField(java_params, in_memory_field, params.in_memory);

    return local_ref(env, java_params);
}

ag::dnsproxy_settings ag::android_dnsproxy::marshal_settings(JNIEnv *env,
                                                             jobject java_dnsproxy_settings) {

    auto clazz = env->FindClass(FQN_DNSPROXY_SETTINGS);
    assert(env->IsInstanceOf(java_dnsproxy_settings, clazz));

    auto blocked_response_ttl_field = env->GetFieldID(clazz, "blockedResponseTtlSecs", "J");
    auto dns64_field = env->GetFieldID(clazz, "dns64", "L" FQN_DNS64_SETTINGS ";");
    auto upstreams_field = env->GetFieldID(clazz, "upstreams", "Ljava/util/List;");
    auto fallbacks_field = env->GetFieldID(clazz, "fallbacks", "Ljava/util/List;");
    auto handle_dns_suffixes_field = env->GetFieldID(clazz, "handleDNSSuffixes", "Z");
    auto dns_suffixes_field = env->GetFieldID(clazz, "userDNSSuffixes", "Ljava/util/List;");
    auto listeners_field = env->GetFieldID(clazz, "listeners", "Ljava/util/List;");
    auto filter_params_field = env->GetFieldID(clazz, "filterParams", "Ljava/util/List;");
    auto ipv6_avail_field = env->GetFieldID(clazz, "ipv6Available", "Z");
    auto block_ipv6_field = env->GetFieldID(clazz, "blockIpv6", "Z");
    auto blocking_mode_field = env->GetFieldID(clazz, "blockingMode", "L" FQN_BLOCKING_MODE ";");
    auto custom_blocking_ip4_field = env->GetFieldID(clazz, "customBlockingIpv4", "Ljava/lang/String;");
    auto custom_blocking_ip6_field = env->GetFieldID(clazz, "customBlockingIpv6", "Ljava/lang/String;");
    auto cache_size_field = env->GetFieldID(clazz, "dnsCacheSize", "J");
    auto optimistic_cache_field = env->GetFieldID(clazz, "optimisticCache", "Z");

    ag::dnsproxy_settings settings{};

    settings.blocked_response_ttl_secs = env->GetLongField(java_dnsproxy_settings, blocked_response_ttl_field);

    if (local_ref upstreams{env, env->GetObjectField(java_dnsproxy_settings, upstreams_field)}) {
        m_utils.iterate(env, upstreams.get(), [&](local_ref<jobject> &&java_upstream_settings) {
            settings.upstreams.push_back(marshal_upstream(env, java_upstream_settings.get()));
        });
    }

    if (local_ref fallbacks{env, env->GetObjectField(java_dnsproxy_settings, fallbacks_field)}) {
        m_utils.iterate(env, fallbacks.get(), [&](local_ref<jobject> &&java_upstream_settings) {
            settings.fallbacks.push_back(marshal_upstream(env, java_upstream_settings.get()));
        });
    }

    settings.handle_dns_suffixes = env->GetBooleanField(java_dnsproxy_settings, handle_dns_suffixes_field);
    if (local_ref dns_suffixes{env, env->GetObjectField(java_dnsproxy_settings, dns_suffixes_field)}) {
        m_utils.iterate(env, dns_suffixes.get(), [&](local_ref<jobject> &&java_str) {
            m_utils.visit_string(env, java_str.get(), [&](const char *str, jsize len) {
                settings.dns_suffixes.emplace_back(str, len); // Copy
            });
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

    if (auto blocking_mode = env->GetObjectField(java_dnsproxy_settings, blocking_mode_field)) {
        settings.blocking_mode = (ag::dnsproxy_blocking_mode) m_utils.get_enum_ordinal(env, blocking_mode);
    }

    if (auto custom_ip4 = env->GetObjectField(java_dnsproxy_settings, custom_blocking_ip4_field)) {
        m_utils.visit_string(env, custom_ip4, [&settings](const char *str, jsize len) {
            settings.custom_blocking_ipv4.assign(str, len);
        });
    }

    if (auto custom_ip6 = env->GetObjectField(java_dnsproxy_settings, custom_blocking_ip6_field)) {
        m_utils.visit_string(env, custom_ip6, [&settings](const char *str, jsize len) {
            settings.custom_blocking_ipv6.assign(str, len);
        });
    }

    settings.dns_cache_size = std::max((jlong) 0, env->GetLongField(java_dnsproxy_settings, cache_size_field));
    settings.optimistic_cache = env->GetBooleanField(java_dnsproxy_settings, optimistic_cache_field);

    return settings;
}

ag::local_ref<jobject> ag::android_dnsproxy::marshal_settings(JNIEnv *env, const ag::dnsproxy_settings &settings) {
    auto clazz = env->FindClass(FQN_DNSPROXY_SETTINGS);
    auto ctor = env->GetMethodID(clazz, "<init>", "()V");

    auto blocked_response_ttl_field = env->GetFieldID(clazz, "blockedResponseTtlSecs", "J");
    auto dns64_field = env->GetFieldID(clazz, "dns64", "L" FQN_DNS64_SETTINGS ";");
    auto upstreams_field = env->GetFieldID(clazz, "upstreams", "Ljava/util/List;");
    auto fallbacks_field = env->GetFieldID(clazz, "fallbacks", "Ljava/util/List;");
    auto handle_dns_suffixes_field = env->GetFieldID(clazz, "handleDNSSuffixes", "Z");
    auto dns_suffixes_field = env->GetFieldID(clazz, "userDNSSuffixes", "Ljava/util/List;");
    auto listeners_field = env->GetFieldID(clazz, "listeners", "Ljava/util/List;");
    auto filter_params_field = env->GetFieldID(clazz, "filterParams", "Ljava/util/List;");
    auto ipv6_avail_field = env->GetFieldID(clazz, "ipv6Available", "Z");
    auto block_ipv6_field = env->GetFieldID(clazz, "blockIpv6", "Z");
    auto blocking_mode_field = env->GetFieldID(clazz, "blockingMode", "L" FQN_BLOCKING_MODE ";");
    auto custom_blocking_ip4_field = env->GetFieldID(clazz, "customBlockingIpv4", "Ljava/lang/String;");
    auto custom_blocking_ip6_field = env->GetFieldID(clazz, "customBlockingIpv6", "Ljava/lang/String;");
    auto cache_size_field = env->GetFieldID(clazz, "dnsCacheSize", "J");
    auto optimistic_cache_field = env->GetFieldID(clazz, "optimisticCache", "Z");

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

    if (local_ref fallbacks{env, env->GetObjectField(java_settings, fallbacks_field)}) {
        for (auto &upstream : settings.fallbacks) {
            m_utils.collection_add(env, fallbacks.get(), marshal_upstream(env, upstream).get());
        }
    }

    env->SetBooleanField(java_settings, handle_dns_suffixes_field, (jboolean) settings.handle_dns_suffixes);
    if (local_ref dns_suffixes{env, env->GetObjectField(java_settings, dns_suffixes_field)}) {
        for (auto &cur : settings.dns_suffixes) {
            m_utils.collection_add(env, dns_suffixes.get(), m_utils.marshal_string(env, cur).get());
        }
    }

    if (local_ref listeners{env, env->GetObjectField(java_settings, listeners_field)}) {
        for (auto &listener : settings.listeners) {
            m_utils.collection_add(env, listeners.get(), marshal_listener(env, listener).get());
        }
    }

    if (local_ref filter_params{env, env->GetObjectField(java_settings, filter_params_field)}) {
        for (auto &filter_param : settings.filter_params.filters) {
            m_utils.collection_add(env, filter_params.get(), marshal_filter_params(env, filter_param).get());
        }
    }
    env->SetBooleanField(java_settings, ipv6_avail_field, (jboolean) settings.ipv6_available);
    env->SetBooleanField(java_settings, block_ipv6_field, (jboolean) settings.block_ipv6);
    env->SetObjectField(java_settings, blocking_mode_field, m_blocking_mode_values.at((size_t) settings.blocking_mode).get());

    env->SetObjectField(java_settings, custom_blocking_ip4_field, m_utils.marshal_string(env, settings.custom_blocking_ipv4).get());
    env->SetObjectField(java_settings, custom_blocking_ip6_field, m_utils.marshal_string(env, settings.custom_blocking_ipv6).get());

    env->SetLongField(java_settings, cache_size_field, (jlong) settings.dns_cache_size);
    env->SetBooleanField(java_settings, optimistic_cache_field, (jboolean) settings.optimistic_cache);

    return local_ref(env, java_settings);
}

ag::local_ref<jobject> ag::android_dnsproxy::marshal_processed_event(JNIEnv *env,
                                                                     const ag::dns_request_processed_event &event) {

    auto check = m_jni_initialized.load();
    assert(check);

    auto java_event = env->NewObject(m_jclasses.processed_event.get(), m_processed_event_methods.ctor);

    env->SetObjectField(java_event, m_processed_event_fields.domain, m_utils.marshal_string(env, event.domain).get());
    env->SetObjectField(java_event, m_processed_event_fields.type, m_utils.marshal_string(env, event.type).get());
    env->SetObjectField(java_event, m_processed_event_fields.status, m_utils.marshal_string(env, event.status).get());
    env->SetObjectField(java_event, m_processed_event_fields.answer, m_utils.marshal_string(env, event.answer).get());
    env->SetObjectField(java_event, m_processed_event_fields.original_answer, m_utils.marshal_string(env, event.original_answer).get());
    env->SetObjectField(java_event, m_processed_event_fields.error, m_utils.marshal_string(env, event.error).get());
    env->SetObjectField(java_event, m_processed_event_fields.upstream_id, m_utils.marshal_integer(env, event.upstream_id).get());
    env->SetLongField(java_event, m_processed_event_fields.start_time, event.start_time);
    env->SetIntField(java_event, m_processed_event_fields.elapsed, event.elapsed);
    env->SetIntField(java_event, m_processed_event_fields.bytes_sent, event.bytes_sent);
    env->SetIntField(java_event, m_processed_event_fields.bytes_received, event.bytes_received);
    env->SetBooleanField(java_event, m_processed_event_fields.whitelist, event.whitelist);
    env->SetBooleanField(java_event, m_processed_event_fields.cache_hit, event.cache_hit);

    {
        const jsize ids_len = event.filter_list_ids.size();
        local_ref ids(env, env->NewIntArray(ids_len));
        env->SetIntArrayRegion(ids.get(), 0, ids_len, (jint *) event.filter_list_ids.data());
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

    auto [ret, _] = m_actual_proxy.init(cpp_settings, cpp_events);
    return ret;
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

jstring ag::android_dnsproxy::test_upstream(JNIEnv *env, jobject upstream_settings, jobject events_adapter) {
    m_events = global_ref(get_vm(env), events_adapter);
    auto err = ag::test_upstream(marshal_upstream(env, upstream_settings),
                                 marshal_events(env, events_adapter).on_certificate_verification);
    if (err) {
        return (jstring) env->NewLocalRef(m_utils.marshal_string(env, *err).get());
    }
    return NULL;
}

ag::android_dnsproxy::android_dnsproxy(JavaVM *vm) : m_utils(vm) {
    scoped_jni_env env(vm, 16);

    jclass c = (m_jclasses.processed_event = global_ref(vm, env->FindClass(FQN_REQ_PROC_EVENT))).get();
    m_processed_event_methods.ctor = env->GetMethodID(c, "<init>", "()V");
    m_processed_event_fields.error = env->GetFieldID(c, "error", "Ljava/lang/String;");
    m_processed_event_fields.status = env->GetFieldID(c, "status", "Ljava/lang/String;");
    m_processed_event_fields.answer = env->GetFieldID(c, "answer", "Ljava/lang/String;");
    m_processed_event_fields.original_answer = env->GetFieldID(c, "originalAnswer", "Ljava/lang/String;");
    m_processed_event_fields.upstream_id = env->GetFieldID(c, "upstreamId", "Ljava/lang/Integer;");
    m_processed_event_fields.domain = env->GetFieldID(c, "domain", "Ljava/lang/String;");
    m_processed_event_fields.type = env->GetFieldID(c, "type", "Ljava/lang/String;");
    m_processed_event_fields.bytes_received = env->GetFieldID(c, "bytesReceived", "I");
    m_processed_event_fields.bytes_sent = env->GetFieldID(c, "bytesSent", "I");
    m_processed_event_fields.elapsed = env->GetFieldID(c, "elapsed", "I");
    m_processed_event_fields.start_time = env->GetFieldID(c, "startTime", "J");
    m_processed_event_fields.whitelist = env->GetFieldID(c, "whitelist", "Z");
    m_processed_event_fields.rules = env->GetFieldID(c, "rules", "Ljava/util/List;");
    m_processed_event_fields.filter_list_ids = env->GetFieldID(c, "filterListIds", "[I");
    m_processed_event_fields.cache_hit = env->GetFieldID(c, "cacheHit", "Z");

    c = (m_jclasses.cert_verify_event = global_ref(vm, env->FindClass(FQN_CERT_VERIFY_EVENT))).get();
    m_cert_verify_event_methods.ctor = env->GetMethodID(c, "<init>", "()V");
    m_cert_verify_event_fields.certificate = env->GetFieldID(c, "certificate", "[B");
    m_cert_verify_event_fields.chain = env->GetFieldID(c, "chain", "Ljava/util/List;");

    c = (m_jclasses.events_interface = global_ref(vm, env->FindClass(FQN_DNSPROXY_EVENTS))).get();
    m_events_interface_methods.on_request_processed = env->GetMethodID(
            c, "onRequestProcessed", "(L" FQN_REQ_PROC_EVENT ";)V");
    m_events_interface_methods.on_certificate_verification = env->GetMethodID(
            c, "onCertificateVerification", "(L" FQN_CERT_VERIFY_EVENT ";)Ljava/lang/String;");

    m_protocol_enum_values = m_utils.get_enum_values(env.get(), FQN_LISTENER_PROTOCOL);
    m_blocking_mode_values = m_utils.get_enum_values(env.get(), FQN_BLOCKING_MODE);

    m_jni_initialized.store(true);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_adguard_dnslibs_proxy_DnsProxy_version(JNIEnv *env, jclass clazz) {
    (void) clazz;
    return env->NewStringUTF(ag::dnsproxy::version()); // Assume version is already valid UTF-8/CESU-8
}
