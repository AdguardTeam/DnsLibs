#include <assert.h>
#include <memory>

#include "android_dnsstamp.h"
#include "jni_defs.h"
#include "jni_utils.h"

using namespace ag;
using namespace ag::dns;
using namespace ag::jni;

static std::unique_ptr<AndroidDnsStamp> g_dnsstamp_impl;

static int init_dnsstamp_impl(JNIEnv *env) {
    JavaVM *vm = nullptr;
    env->GetJavaVM(&vm);
    g_dnsstamp_impl = std::make_unique<AndroidDnsStamp>(vm);
    return 0;
}

static AndroidDnsStamp &dnsstamp_impl(JNIEnv *env) {
    int ensure_dnsstamp_impl_initialized [[maybe_unused]] = init_dnsstamp_impl(env);
    return *g_dnsstamp_impl;
}

AndroidDnsStamp::AndroidDnsStamp(JavaVM *vm)
        : m_utils(vm) {
    ScopedJniEnv env(vm, 1);
    m_dnsstamp_prototype_values = m_utils.get_enum_values(env.get(), FQN_DNSSTAMP_PROTOTYPE);
}

LocalRef<jobject> AndroidDnsStamp::marshal_dnsstamp(JNIEnv *env, const ServerStamp &stamp) {

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
                m_utils.marshal_uint8_view(env, {stamp.server_pk.data(), stamp.server_pk.size()}).get());
    }

    clazz = env->FindClass(FQN_DNSSTAMP_INFORMAL_PROPERTIES);
    auto to_enum_set_method = env->GetStaticMethodID(clazz, "toEnumSet", "(I)Ljava/util/EnumSet;");
    if (stamp.props.has_value()) {
        if (LocalRef props{env, env->CallStaticObjectMethod(clazz, to_enum_set_method, (jint) stamp.props.value())}) {
            env->SetObjectField(dns_stamp, props_field, props.get());
        }
    }

    if (!stamp.hashes.empty()) {
        clazz = env->FindClass("java/util/ArrayList");
        ctor = env->GetMethodID(clazz, "<init>", "()V");
        LocalRef<jobject> hashes{env, env->NewObject(clazz, ctor)};
        auto add_method = env->GetMethodID(clazz, "add", "(Ljava/lang/Object;)Z");
        for (const std::vector<uint8_t> &h : stamp.hashes) {
            env->CallBooleanMethod(
                    hashes.get(), add_method, m_utils.marshal_uint8_view(env, {h.data(), h.size()}).get());
        }
        env->SetObjectField(dns_stamp, hashes_field, hashes.get());
    }

    return {env, dns_stamp};
}

ServerStamp AndroidDnsStamp::marshal_dnsstamp(JNIEnv *env, jobject java_dns_stamp) {
    auto clazz = env->FindClass(FQN_DNSSTAMP);

    auto proto_field = env->GetFieldID(clazz, "proto", "L" FQN_DNSSTAMP_PROTOTYPE ";");
    auto server_addr_field = env->GetFieldID(clazz, "serverAddr", "Ljava/lang/String;");
    auto provider_name_field = env->GetFieldID(clazz, "providerName", "Ljava/lang/String;");
    auto path_field = env->GetFieldID(clazz, "path", "Ljava/lang/String;");
    auto server_pk_field = env->GetFieldID(clazz, "serverPublicKey", "[B");
    auto props_field = env->GetFieldID(clazz, "properties", "Ljava/util/EnumSet;");
    auto hashes_field = env->GetFieldID(clazz, "hashes", "Ljava/util/ArrayList;");

    ServerStamp stamp;
    if (auto value = LocalRef<jobject>(env, env->GetObjectField(java_dns_stamp, proto_field))) {
        clazz = env->FindClass(FQN_DNSSTAMP_PROTOTYPE);
        auto ordinal_method = env->GetMethodID(clazz, "ordinal", "()I");
        stamp.proto = (StampProtoType) env->CallIntMethod(value.get(), ordinal_method);
    }
    if (auto value = LocalRef<jstring>(env, (jstring) env->GetObjectField(java_dns_stamp, server_addr_field))) {
        stamp.server_addr_str = JniUtils::marshal_string(env, value.get());
    }
    if (auto value = LocalRef<jstring>(env, (jstring) env->GetObjectField(java_dns_stamp, provider_name_field))) {
        stamp.provider_name = JniUtils::marshal_string(env, value.get());
    }
    if (auto value = LocalRef<jstring>(env, (jstring) env->GetObjectField(java_dns_stamp, path_field))) {
        stamp.path = JniUtils::marshal_string(env, value.get());
    }
    if (auto value = LocalRef<jbyteArray>(env, (jbyteArray) env->GetObjectField(java_dns_stamp, server_pk_field))) {
        stamp.server_pk.resize(env->GetArrayLength(value.get()));
        env->GetByteArrayRegion(value.get(), 0, stamp.server_pk.size(), (jbyte *) &stamp.server_pk[0]);
    }
    if (auto value = LocalRef<jobject>(env, env->GetObjectField(java_dns_stamp, props_field))) {
        clazz = env->FindClass("java/util/EnumSet");
        auto to_array_method = env->GetMethodID(clazz, "toArray", "()[Ljava/lang/Object;");
        auto enum_set = LocalRef<jobjectArray>(env, (jobjectArray) env->CallObjectMethod(value.get(), to_array_method));
        clazz = env->FindClass(FQN_DNSSTAMP_INFORMAL_PROPERTIES);
        auto flag_value_field = env->GetFieldID(clazz, "flagValue", "I");
        uint64_t props = 0;
        for (jint i = 0; i < env->GetArrayLength(enum_set.get()); i++) {
            LocalRef<jobject> enum_value(env, env->GetObjectArrayElement(enum_set.get(), i));
            props |= (uint64_t) env->GetIntField(enum_value.get(), flag_value_field);
        }
        stamp.props = (ServerInformalProperties) props;
    }
    if (auto value = LocalRef<jobject>(env, env->GetObjectField(java_dns_stamp, hashes_field))) {
        clazz = env->FindClass("java/util/ArrayList");
        auto size_method = env->GetMethodID(clazz, "size", "()I");
        auto get_method = env->GetMethodID(clazz, "get", "(I)Ljava/lang/Object;");
        jint size = env->CallIntMethod(value.get(), size_method);
        for (jint i = 0; i < size; i++) {
            auto jhash = LocalRef<jbyteArray>{env, (jbyteArray) env->CallObjectMethod(value.get(), get_method, i)};
            std::vector<uint8_t> hash;
            hash.resize(env->GetArrayLength(jhash.get()));
            env->GetByteArrayRegion(jhash.get(), 0, hash.size(), (jbyte *) &hash[0]);
            stamp.hashes.push_back(std::move(hash));
        }
    }

    return stamp;
}

extern "C" JNIEXPORT jstring JNICALL Java_com_adguard_dnslibs_proxy_DnsStamp_toString(JNIEnv *env, jobject thiz) {
    AndroidDnsStamp impl = dnsstamp_impl(env);
    auto stamp = impl.marshal_dnsstamp(env, thiz);
    return (jstring) env->NewLocalRef(JniUtils::marshal_string(env, stamp.str()).get());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_adguard_dnslibs_proxy_DnsStamp_getPrettyUrl(JNIEnv *env, jobject thiz) {
    AndroidDnsStamp impl = dnsstamp_impl(env);
    auto stamp = impl.marshal_dnsstamp(env, thiz);
    return (jstring) env->NewLocalRef(JniUtils::marshal_string(env, stamp.pretty_url(false)).get());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_adguard_dnslibs_proxy_DnsStamp_getPrettierUrl(JNIEnv *env, jobject thiz) {
    AndroidDnsStamp impl = dnsstamp_impl(env);
    auto stamp = impl.marshal_dnsstamp(env, thiz);
    return (jstring) env->NewLocalRef(JniUtils::marshal_string(env, stamp.pretty_url(true)).get());
}

extern "C" JNIEXPORT jobject JNICALL Java_com_adguard_dnslibs_proxy_DnsStamp_parse0(
        JNIEnv *env, jclass clazz, jstring stamp_str) {
    auto stamp = ServerStamp::from_string(JniUtils::marshal_string(env, stamp_str));

    if (stamp.has_error()) {
        env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), stamp.error()->str().c_str());
        return nullptr;
    }

    AndroidDnsStamp impl = dnsstamp_impl(env);
    return env->NewLocalRef(impl.marshal_dnsstamp(env, stamp.value()).get());
}
