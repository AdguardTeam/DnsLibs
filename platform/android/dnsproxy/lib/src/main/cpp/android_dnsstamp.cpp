#include <assert.h>
#include <memory>
#include "android_dnsstamp.h"
#include "jni_defs.h"
#include "jni_utils.h"

static std::unique_ptr<ag::android_dnsstamp> g_dnsstamp_impl;

static int init_dnsstamp_impl(JNIEnv *env) {
    JavaVM *vm = nullptr;
    env->GetJavaVM(&vm);
    g_dnsstamp_impl = std::make_unique<ag::android_dnsstamp>(vm);
    return 0;
}

static ag::android_dnsstamp &dnsstamp_impl(JNIEnv *env) {
    int ensure_dnsstamp_impl_initialized [[maybe_unused]] = init_dnsstamp_impl(env);
    return *g_dnsstamp_impl;
}

ag::android_dnsstamp::android_dnsstamp(JavaVM *vm) : m_utils(vm) {
    ag::scoped_jni_env env(vm, 1);
    m_dnsstamp_prototype_values = m_utils.get_enum_values(env.get(), FQN_DNSSTAMP_PROTOTYPE);
}

ag::local_ref<jobject>
ag::android_dnsstamp::marshal_dnsstamp(JNIEnv *env, const ag::server_stamp &stamp) {

    auto clazz = env->FindClass(FQN_DNSSTAMP);
    auto ctor = env->GetMethodID(clazz, "<init>", "()V");

    auto proto_field = env->GetFieldID(clazz, "proto", "L" FQN_DNSSTAMP_PROTOTYPE ";");
    auto server_addr_field = env->GetFieldID(clazz, "serverAddr", "Ljava/lang/String;");
    auto provider_name_field = env->GetFieldID(clazz, "providerName", "Ljava/lang/String;");
    auto path_field = env->GetFieldID(clazz, "path", "Ljava/lang/String;");
    auto server_pk_field = env->GetFieldID(clazz, "serverPublicKey", "[B");
    auto props_field = env->GetFieldID(clazz, "properties", "Ljava/util/EnumSet;");
    auto hashes_field = env->GetFieldID(clazz, "hashes", "Ljava/util/ArrayList;");

    auto dns_stamp = env->NewObject(clazz, ctor);

    env->SetObjectField(dns_stamp, proto_field, m_dnsstamp_prototype_values.at((size_t) stamp.proto).get());
    env->SetObjectField(dns_stamp, server_addr_field, m_utils.marshal_string(env, stamp.server_addr_str).get());
    env->SetObjectField(dns_stamp, provider_name_field, m_utils.marshal_string(env, stamp.provider_name).get());
    env->SetObjectField(dns_stamp, path_field, m_utils.marshal_string(env, stamp.path).get());

    if (!stamp.server_pk.empty()) {
        env->SetObjectField(dns_stamp, server_pk_field,
                            m_utils.marshal_uint8_view(env, { stamp.server_pk.data(), stamp.server_pk.size() }).get());
    }

    clazz = env->FindClass(FQN_DNSSTAMP_INFORMAL_PROPERTIES);
    auto to_enum_set_method = env->GetStaticMethodID(clazz, "toEnumSet", "(I)Ljava/util/EnumSet;");
    if (local_ref props{ env, env->CallStaticObjectMethod(clazz, to_enum_set_method, (jint)stamp.props) }) {
        env->SetObjectField(dns_stamp, props_field, props.get());
    }

    if (!stamp.hashes.empty()) {
        clazz = env->FindClass("java/util/ArrayList");
        ctor = env->GetMethodID(clazz, "<init>", "()V");
        local_ref<jobject> hashes{env, env->NewObject(clazz, ctor)};
        auto add_method = env->GetMethodID(clazz, "add", "(Ljava/lang/Object;)Z");
        for (const std::vector<uint8_t> &h : stamp.hashes) {
            env->CallBooleanMethod(hashes.get(), add_method, m_utils.marshal_uint8_view(env, {h.data(), h.size()}).get());
        }
        env->SetObjectField(dns_stamp, hashes_field, hashes.get());
    }

    return {env, dns_stamp};
}

ag::server_stamp ag::android_dnsstamp::marshal_dnsstamp(JNIEnv *env, jobject java_dns_stamp) {
    auto clazz = env->FindClass(FQN_DNSSTAMP);

    auto proto_field = env->GetFieldID(clazz, "proto", "L" FQN_DNSSTAMP_PROTOTYPE ";");
    auto server_addr_field = env->GetFieldID(clazz, "serverAddr", "Ljava/lang/String;");
    auto provider_name_field = env->GetFieldID(clazz, "providerName", "Ljava/lang/String;");
    auto path_field = env->GetFieldID(clazz, "path", "Ljava/lang/String;");
    auto server_pk_field = env->GetFieldID(clazz, "serverPublicKey", "[B");
    auto props_field = env->GetFieldID(clazz, "properties", "Ljava/util/EnumSet;");
    auto hashes_field = env->GetFieldID(clazz, "hashes", "Ljava/util/ArrayList;");

    ag::server_stamp stamp;
    if (auto value = local_ref<jobject>(env, env->GetObjectField(java_dns_stamp, proto_field))) {
        clazz = env->FindClass(FQN_DNSSTAMP_PROTOTYPE);
        auto ordinal_method = env->GetMethodID(clazz, "ordinal", "()I");
        stamp.proto = (stamp_proto_type) env->CallIntMethod(value.get(), ordinal_method);
    }
    if (auto value = local_ref<jstring>(env, (jstring)env->GetObjectField(java_dns_stamp, server_addr_field))) {
        stamp.server_addr_str = ag::jni_utils::marshal_string(env, value.get());
    }
    if (auto value = local_ref<jstring>(env, (jstring)env->GetObjectField(java_dns_stamp, provider_name_field))) {
        stamp.provider_name = ag::jni_utils::marshal_string(env, value.get());
    }
    if (auto value = local_ref<jstring>(env, (jstring)env->GetObjectField(java_dns_stamp, path_field))) {
        stamp.path = ag::jni_utils::marshal_string(env, value.get());
    }
    if (auto value = local_ref<jbyteArray>(env, (jbyteArray)env->GetObjectField(java_dns_stamp, server_pk_field))) {
        stamp.server_pk.resize(env->GetArrayLength(value.get()));
        env->GetByteArrayRegion(value.get(), 0, stamp.server_pk.size(), (jbyte *)&stamp.server_pk[0]);
    }
    if (auto value = local_ref<jobject>(env, env->GetObjectField(java_dns_stamp, props_field))) {
        clazz = env->FindClass("java/util/EnumSet");
        auto to_array_method = env->GetMethodID(clazz, "toArray", "()[Ljava/lang/Object;");
        auto enum_set = local_ref<jobjectArray>(env, (jobjectArray)env->CallObjectMethod(value.get(), to_array_method));
        clazz = env->FindClass(FQN_DNSSTAMP_INFORMAL_PROPERTIES);
        auto flag_value_field = env->GetFieldID(clazz, "flagValue", "I");
        uint64_t props = 0;
        for (jint i = 0; i < env->GetArrayLength(enum_set.get()); i++) {
            local_ref<jobject> enum_value(env, env->GetObjectArrayElement(enum_set.get(), i));
            props |= (uint64_t)env->GetIntField(enum_value.get(), flag_value_field);
        }
        stamp.props = (server_informal_properties)props;
    }
    if (auto value = local_ref<jobject>(env, env->GetObjectField(java_dns_stamp, hashes_field))) {
        clazz = env->FindClass("java/util/ArrayList");
        auto size_method = env->GetMethodID(clazz, "size", "()I");
        auto get_method  = env->GetMethodID(clazz, "get", "(I)Ljava/lang/Object;");
        jint size = env->CallIntMethod(value.get(), size_method);
        for (jint i = 0; i < size; i++) {
            auto jhash = local_ref<jbyteArray>{env, (jbyteArray)env->CallObjectMethod(value.get(), get_method, i)};
            std::vector<uint8_t> hash;
            hash.resize(env->GetArrayLength(jhash.get()));
            env->GetByteArrayRegion(jhash.get(), 0, hash.size(), (jbyte *)&hash[0]);
            stamp.hashes.push_back(std::move(hash));
        }
    }

    return stamp;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_adguard_dnslibs_proxy_DnsStamp_toString(JNIEnv *env, jobject thiz) {
    ag::android_dnsstamp impl = dnsstamp_impl(env);
    auto stamp = impl.marshal_dnsstamp(env, thiz);
    return (jstring)env->NewLocalRef(ag::jni_utils::marshal_string(env, stamp.str()).get());
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_adguard_dnslibs_proxy_DnsStamp_getPrettyUrl(JNIEnv *env, jobject thiz) {
    ag::android_dnsstamp impl = dnsstamp_impl(env);
    auto stamp = impl.marshal_dnsstamp(env, thiz);
    return (jstring)env->NewLocalRef(ag::jni_utils::marshal_string(env, stamp.pretty_url(false)).get());
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_adguard_dnslibs_proxy_DnsStamp_getPrettierUrl(JNIEnv *env, jobject thiz) {
    ag::android_dnsstamp impl = dnsstamp_impl(env);
    auto stamp = impl.marshal_dnsstamp(env, thiz);
    return (jstring)env->NewLocalRef(ag::jni_utils::marshal_string(env, stamp.pretty_url(true)).get());
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_adguard_dnslibs_proxy_DnsStamp_parse0(JNIEnv *env, jclass clazz, jstring stamp_str) {
    auto [stamp, err] = ag::server_stamp::from_string(ag::jni_utils::marshal_string(env, stamp_str));

    if (err) {
        env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), err->c_str());
        return nullptr;
    }

    ag::android_dnsstamp impl = dnsstamp_impl(env);
    return env->NewLocalRef(impl.marshal_dnsstamp(env, stamp).get());
}
