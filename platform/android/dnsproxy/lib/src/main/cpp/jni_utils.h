#pragma once

#include <jni.h>
#include <functional>
#include <string_view>

#include "common/defs.h"

#include "scoped_jni_env.h"

namespace ag::jni {

/**
 * NewGlobalRef in ctor, DeleteGlobalRef in dtor.
 */
template <typename T>
class GlobalRef {
private:
    JavaVM *m_vm{};
    T m_ref{};

    void delete_global_ref() const {
        if (m_vm) {
            ScopedJniEnv env(m_vm, 1);
            env->DeleteGlobalRef(m_ref);
        }
    }

public:
    GlobalRef() = default;

    GlobalRef(JavaVM *vm, T ref) : m_vm{vm} {
        ScopedJniEnv env(vm, 1);
        m_ref = (T) env->NewGlobalRef(ref);
    }

    GlobalRef(const GlobalRef &other) {
        *this = other;
    }

    GlobalRef &operator=(const GlobalRef &other) {
        if (&other != this) {
            delete_global_ref();
            m_vm = other.m_vm;
            ScopedJniEnv env(m_vm, 1);
            m_ref = (T) env->NewGlobalRef(other.m_ref);
        }
        return *this;
    }

    GlobalRef(GlobalRef &&other) noexcept {
        *this = std::move(other);
    }

    GlobalRef &operator=(GlobalRef &&other) noexcept {
        if (&other != this) {
            delete_global_ref();
            m_vm = other.m_vm;
            m_ref = other.m_ref;
            other.m_vm = {};
            other.m_ref = {};
        }
        return *this;
    }

    ~GlobalRef() {
        delete_global_ref();
    }

    T get() const {
        return m_ref;
    }

    explicit operator bool() {
        return m_ref;
    }
};


/**
 * DeleteLocalRef in dtor.
 */
template <typename T>
class LocalRef {
private:
    JNIEnv *m_env{};
    T m_ref{};

    void delete_local_ref() {
        if (m_env) {
            m_env->DeleteLocalRef(m_ref);
        }
    }

public:
    LocalRef() = default;

    LocalRef(JNIEnv *env, T ref) : m_env{env}, m_ref{ref} {}

    LocalRef(JNIEnv *env, const GlobalRef<T> &global) : m_env{env}, m_ref{env->NewLocalRef(global.get())} {}

    LocalRef(const LocalRef &) = delete;

    LocalRef &operator=(const LocalRef &) = delete;

    LocalRef(LocalRef &&other) noexcept {
        *this = std::move(other);
    }

    LocalRef &operator=(LocalRef &&other) noexcept {
        if (&other != this) {
            delete_local_ref();
            m_env = other.m_env;
            m_ref = other.m_ref;
            other.m_env = {};
            other.m_ref = {};
        }
        return *this;
    }

    ~LocalRef() {
        delete_local_ref();
    }

    T get() const {
        return m_ref;
    }

    explicit operator bool() {
        return m_ref;
    }
};

/**
 * This class is NOT thread-safe!
 */
class JniUtils {
private:
    struct {
        GlobalRef<jclass> collection;
        GlobalRef<jclass> iterable;
        GlobalRef<jclass> iterator;
        GlobalRef<jclass> string;
        GlobalRef<jclass> enum_base;
        GlobalRef<jclass> integer;
    } m_jclasses{};

    struct {
        jmethodID ordinal;
    } m_enum_methods{};

    struct {
        jmethodID add;
    } m_collection_methods{};

    struct {
        jmethodID iterator;
    } m_iterable_methods{};

    struct {
        jmethodID has_next;
        jmethodID next;
    } m_iterator_methods{};

    struct {
        jmethodID value_of;
        jmethodID int_value;
    } m_integer_methods{};

public:

    /**
     * Initialize global refs.
     */
    explicit JniUtils(JavaVM *vm);

    /**
     * Call `f` for each object in `iterable`.
     */
    void iterate(JNIEnv *env, jobject iterable, const std::function<void(LocalRef<jobject> &&)> &f);

    /**
     * Call `f` for `string`.
     * Callback receives a C string encoded in UTF8-modified and released after calling `f`.
     */
    static void visit_string(JNIEnv *env, jobject string, const std::function<void(const char *, jsize)> &f);

    /**
     * Marshal a C++ string view to Java String.
     */
    static LocalRef<jstring> marshal_string(JNIEnv *env, std::string_view str);

    /**
     * Marshal a Java string to C++.
     */
    static std::string marshal_string(JNIEnv *env, jstring str);

    /**
     * Marshal C++ std::optional<int32_t> to Java Integer.
     */
    LocalRef<jobject> marshal_integer(JNIEnv *env, const std::optional<int32_t>& value);

    /**
     * Marshal a Java Integer to C++ std::optional<int32_t>.
     */
    std::optional<int32_t> marshal_integer(JNIEnv *env, jobject value);

    /**
     * Copy a Uint8View to a new Java byte array.
     */
    static LocalRef<jbyteArray> marshal_uint8_view(JNIEnv *env, Uint8View v);

    /**
     * Add `o` to `collection`.
     * @return Whether successful.
     */
    bool collection_add(JNIEnv *env, jobject collection, jobject o);

    /**
     * @param enum_class The fully qualified name of a Java enum.
     * @return The enum's values.
     */
    std::vector<GlobalRef<jobject>> get_enum_values(JNIEnv *env, const std::string &enum_class);

    /**
     * @return The ordinal of the given enum value. See Javadoc for definition of ordinal.
     */
    jint get_enum_ordinal(JNIEnv *env, jobject enum_value);

};

}
