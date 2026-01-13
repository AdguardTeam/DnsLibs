#include "android_tun_listener.h"

#include <jni.h>
#include <memory>

#include "dns/proxy/tun_listener.h"
#include "jni_defs.h"
#include "jni_utils.h"
#include "scoped_jni_env.h"

using namespace ag;
using namespace ag::dns;
using namespace ag::jni;

extern "C" JNIEXPORT jlong JNICALL Java_com_adguard_dnslibs_proxy_DnsTunListener_create(JNIEnv *env, jobject thiz) {
    return (jlong) new AndroidTunListener(get_vm(env));
}

extern "C" JNIEXPORT void JNICALL Java_com_adguard_dnslibs_proxy_DnsTunListener_delete(
        JNIEnv *env, jobject thiz, jlong native_ptr) {
    delete (AndroidTunListener *)native_ptr;
}

extern "C" JNIEXPORT jobject JNICALL Java_com_adguard_dnslibs_proxy_DnsTunListener_init(
        JNIEnv *env, jobject thiz, jlong native_ptr, jint fd, jint mtu, jobject request_callback) {
    auto *listener = (AndroidTunListener *)native_ptr;
    assert(listener);
    return listener->init(env, fd, mtu, request_callback);
}

extern "C" JNIEXPORT void JNICALL Java_com_adguard_dnslibs_proxy_DnsTunListener_deinit(
        JNIEnv *env, jobject thiz, jlong native_ptr) {
    auto *listener = (AndroidTunListener *)native_ptr;
    assert(listener);
    listener->deinit(env);
}

AndroidTunListener::AndroidTunListener(JavaVM *vm)
        : m_utils(vm) {
    ScopedJniEnv env(vm, 16);
    
    // Get RequestCallback class and methods
    jclass c = (m_jclasses.request_callback_class = GlobalRef(
                        vm, env->FindClass(FQN_DNSTUNLISTENER_REQUEST_CALLBACK))).get();
    m_request_callback_methods.on_request = env->GetMethodID(c, "onRequest", "([B)[B");
    
    m_jni_initialized.store(true);
}

TunListener::RequestCallback AndroidTunListener::marshal_request_callback(JNIEnv *env, jobject request_callback) {
    if (!request_callback) {
        return nullptr;
    }
    
    m_request_callback = GlobalRef(get_vm(env), request_callback);
    
    auto vm = get_vm(env);
    assert(vm);
    
    return [this, vm](Uint8View request, TunListener::Completion completion) {
        assert(m_jni_initialized.load());
        
        ScopedJniEnv scoped_env(vm, 16);
        
        // Convert request to Java byte array
        jni::LocalRef<jbyteArray> java_request{scoped_env.get(), scoped_env->NewByteArray(request.size())};
        assert(java_request);
        
        scoped_env->SetByteArrayRegion(java_request.get(), 0, request.size(), (const jbyte *)request.data());
        
        // Call Java method and get reply synchronously
        jni::LocalRef<jbyteArray> java_reply{scoped_env.get(),
                (jbyteArray)scoped_env->CallObjectMethod(
                        m_request_callback.get(), m_request_callback_methods.on_request, java_request.get())};
        
        if (scoped_env->ExceptionCheck()) {
            scoped_env->ExceptionClear();
            assert(false);
        }
        
        // Convert reply back to C++ and call completion
        if (java_reply) {
            jsize reply_len = scoped_env->GetArrayLength(java_reply.get());
            if (reply_len > 0) {
                jbyte *reply_data = scoped_env->GetByteArrayElements(java_reply.get(), nullptr);
                if (reply_data) {
                    completion(Uint8View{(const uint8_t *)reply_data, (size_t)reply_len});
                    scoped_env->ReleaseByteArrayElements(java_reply.get(), reply_data, JNI_ABORT);
                } else {
                    completion(Uint8View{});
                }
            } else {
                completion(Uint8View{});
            }
        } else {
            completion(Uint8View{});
        }
    };
}

LocalRef<jobject> AndroidTunListener::marshal_init_result(
        JNIEnv *env, const Error<TunListener::InitError> &init_result) {
    auto clazz = env->FindClass(FQN_DNSTUNLISTENER_INIT_RESULT);
    auto ctor = env->GetMethodID(clazz, "<init>", "()V");
    auto error_field = env->GetFieldID(clazz, "error", "Ljava/lang/String;");
    
    LocalRef<jobject> java_result{env, env->NewObject(clazz, ctor)};
    
    if (init_result) {
        env->SetObjectField(java_result.get(), error_field, m_utils.marshal_string(env, init_result->str()).get());
    }
    
    return java_result;
}

jobject AndroidTunListener::init(JNIEnv *env, jint fd, jint mtu, jobject request_callback) {
    assert(m_jni_initialized.load());
    
    auto cpp_request_callback = marshal_request_callback(env, request_callback);
    
    return marshal_init_result(env, m_listener.init(fd, mtu, std::move(cpp_request_callback))).release();
}

void AndroidTunListener::deinit(JNIEnv *env) {
    assert(m_jni_initialized.load());
    
    m_listener.deinit();
    m_jni_initialized.store(false);
}
