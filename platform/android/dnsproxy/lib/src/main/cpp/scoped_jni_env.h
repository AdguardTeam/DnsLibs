#pragma once

#include <jni.h>
#include <pthread.h>

namespace ag {

/**
 * A helper to get the JavaVM from JNIEnv.
 */
inline JavaVM *get_vm(JNIEnv *env) {
    JavaVM *vm{};
    auto ret = env->GetJavaVM(&vm);
    return 0 == ret ? vm : nullptr;
}

/**
 * Attaches the current thread, if necessary, and pushes a local reference frame. Reverses that in dtor.
 */
class scoped_jni_env {
private:
    JavaVM *m_vm{};
    JNIEnv *m_env{};

public:
    scoped_jni_env(JavaVM *vm, jint max_local_refs) {
        m_vm = vm;

        int64_t ret = m_vm->GetEnv((void **) &m_env, JNI_VERSION_1_2);
        assert(JNI_EDETACHED == ret || JNI_OK == ret);
        if (JNI_EDETACHED == ret) {
#if __ANDROID__
            ret = m_vm->AttachCurrentThread(&m_env, nullptr);
#else
            ret = m_vm->AttachCurrentThread((void **) &m_env, nullptr);
#endif
            assert(JNI_OK == ret);

            static pthread_key_t tls_key{};
            static pthread_once_t once_control = PTHREAD_ONCE_INIT;
            ret = pthread_once(&once_control, [] {
                auto ret = pthread_key_create(&tls_key, [](void *arg) {
                    auto vm = (JavaVM *) arg;
                    if (vm) {
                        vm->DetachCurrentThread();
                    }
                });
                assert(0 == ret);
            });
            assert(0 == ret);

            ret = pthread_setspecific(tls_key, vm);
            assert(0 == ret);
        }

        ret = m_env->PushLocalFrame(max_local_refs);
        assert(0 == ret);
    }

    ~scoped_jni_env() {
        m_env->PopLocalFrame(nullptr);
    }

    JNIEnv *get() const {
        return m_env;
    }

    JNIEnv *operator->() const {
        return get();
    }
};

} // namespace ag
