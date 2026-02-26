#include "android_tun_listener.h"

#include <jni.h>
#include <memory>
#include <mutex>
#include <unordered_map>

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

extern "C" JNIEXPORT void JNICALL 
Java_com_adguard_dnslibs_proxy_DnsTunListener_00024NativeReplyHandler_nativeSendReply(
        JNIEnv *env, jclass clazz, jlong native_ptr, jlong completion_id, jbyteArray reply) {
    auto *listener = (AndroidTunListener *)native_ptr;
    assert(listener);
    listener->send_reply(env, completion_id, reply);
}

AndroidTunListener::AndroidTunListener(JavaVM *vm)
        : m_utils(vm) {
    ScopedJniEnv env(vm, 16);
    
    // Get RequestCallback class and methods
    jclass callback_class = (m_jclasses.request_callback_class = GlobalRef(
                        vm, env->FindClass(FQN_DNSTUNLISTENER_REQUEST_CALLBACK))).get();
    m_request_callback_methods.on_request = env->GetMethodID(callback_class, "onRequest",
        "([BL" FQN_DNSTUNLISTENER_REPLY_HANDLER ";)V");
    
    // Get NativeReplyHandler class and constructor
    jclass handler_class = (m_jclasses.native_reply_handler_class = GlobalRef(
                        vm, env->FindClass(FQN_DNSTUNLISTENER_NATIVE_REPLY_HANDLER))).get();
    m_native_reply_handler_methods.ctor = env->GetMethodID(handler_class, "<init>", "(JJ)V");
    
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
        
        // Generate unique ID for this completion callback
        uint64_t completion_id = m_next_completion_id.fetch_add(1);
        
        // Store completion callback
        {
            std::lock_guard<std::mutex> lock(m_completions_mutex);
            m_completions[completion_id] = std::move(completion);
        }
        
        ScopedJniEnv scoped_env(vm, 16);
        
        // Copy request data because it's only valid during this callback execution
        jni::LocalRef<jbyteArray> java_request{scoped_env.get(), scoped_env->NewByteArray(request.size())};
        assert(java_request);
        
        scoped_env->SetByteArrayRegion(java_request.get(), 0, request.size(), (const jbyte *)request.data());
        
        // Create NativeReplyHandler object with nativePtr and completion_id
        jni::LocalRef<jobject> reply_handler{scoped_env.get(),
            scoped_env->NewObject(m_jclasses.native_reply_handler_class.get(),
                m_native_reply_handler_methods.ctor,
                (jlong)this,
                (jlong)completion_id)};
        
        // Call Java method with request and ReplyHandler object
        scoped_env->CallVoidMethod(
                m_request_callback.get(), 
                m_request_callback_methods.on_request, 
                java_request.get(),
                reply_handler.get());
        
        if (scoped_env->ExceptionCheck()) {
            scoped_env->ExceptionClear();
            // Remove completion on error
            std::lock_guard<std::mutex> lock(m_completions_mutex);
            m_completions.erase(completion_id);
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
    
    // Clear all pending completions
    {
        std::lock_guard<std::mutex> lock(m_completions_mutex);
        m_completions.clear();
    }
    
    m_jni_initialized.store(false);
}

void AndroidTunListener::send_reply(JNIEnv *env, jlong reply_handler_id, jbyteArray reply) {
    assert(m_jni_initialized.load());
    
    // Find and remove the completion callback
    TunListener::Completion completion;
    {
        std::lock_guard<std::mutex> lock(m_completions_mutex);
        auto it = m_completions.find((uint64_t)reply_handler_id);
        if (it == m_completions.end()) {
            // Completion already called or invalid ID
            return;
        }
        completion = std::move(it->second);
        m_completions.erase(it);
    }
    
    // Convert reply to C++ and call completion
    if (reply) {
        jsize reply_len = env->GetArrayLength(reply);
        if (reply_len > 0) {
            jbyte *reply_data = env->GetByteArrayElements(reply, nullptr);
            if (reply_data) {
                completion(Uint8View{(const uint8_t *)reply_data, (size_t)reply_len});
                env->ReleaseByteArrayElements(reply, reply_data, JNI_ABORT);
            } else {
                completion(Uint8View{});
            }
        } else {
            completion(Uint8View{});
        }
    } else {
        completion(Uint8View{});
    }
}
