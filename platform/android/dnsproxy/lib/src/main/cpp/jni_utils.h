#pragma once

#include <jni.h>
#include <ag_defs.h>
#include <functional>
#include <string_view>
#include <scoped_jni_env.h>

namespace ag {

/**
 * NewGlobalRef in ctor, DeleteGlobalRef in dtor.
 */
template <typename T>
class global_ref {
private:
    JavaVM *m_vm{};
    T m_ref{};

    void delete_global_ref() const {
        if (m_vm) {
            scoped_jni_env env(m_vm, 1);
            env->DeleteGlobalRef(m_ref);
        }
    }

public:
    global_ref() = default;

    global_ref(JavaVM *vm, T ref) : m_vm{vm} {
        scoped_jni_env env(vm, 1);
        m_ref = (T) env->NewGlobalRef(ref);
    }

    global_ref(const global_ref &other) {
        *this = other;
    }

    global_ref &operator=(const global_ref &other) {
        if (&other != this) {
            delete_global_ref();
            m_vm = other.m_vm;
            scoped_jni_env env(m_vm, 1);
            m_ref = (T) env->NewGlobalRef(other.m_ref);
        }
        return *this;
    }

    global_ref(global_ref &&other) noexcept {
        *this = std::move(other);
    }

    global_ref &operator=(global_ref &&other) noexcept {
        if (&other != this) {
            delete_global_ref();
            m_vm = other.m_vm;
            m_ref = other.m_ref;
            other.m_vm = {};
            other.m_ref = {};
        }
        return *this;
    }

    ~global_ref() {
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
class local_ref {
private:
    JNIEnv *m_env{};
    T m_ref{};

    void delete_local_ref() {
        if (m_env) {
            m_env->DeleteLocalRef(m_ref);
        }
    }

public:
    local_ref() = default;

    local_ref(JNIEnv *env, T ref) : m_env{env}, m_ref{ref} {}

    local_ref(JNIEnv *env, const global_ref<T> &global) : m_env{env}, m_ref{env->NewLocalRef(global.get())} {}

    local_ref(const local_ref &) = delete;

    local_ref &operator=(const local_ref &) = delete;

    local_ref(local_ref &&other) noexcept {
        *this = std::move(other);
    }

    local_ref &operator=(local_ref &&other) noexcept {
        if (&other != this) {
            delete_local_ref();
            m_env = other.m_env;
            m_ref = other.m_ref;
            other.m_env = {};
            other.m_ref = {};
        }
        return *this;
    }

    ~local_ref() {
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
class jni_utils {
private:
    struct {
        global_ref<jclass> collection;
        global_ref<jclass> iterable;
        global_ref<jclass> iterator;
        global_ref<jclass> string;
        global_ref<jclass> enum_base;
        global_ref<jclass> integer;
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
    explicit jni_utils(JavaVM *vm);

    /**
     * Call `f` for each object in `iterable`.
     */
    void iterate(JNIEnv *env, jobject iterable, const std::function<void(local_ref<jobject> &&)> &f);

    /**
     * Call `f` for `string`.
     * Callback receives a C string encoded in UTF8-modified and released after calling `f`.
     */
    static void visit_string(JNIEnv *env, jobject string, const std::function<void(const char *, jsize)> &f);

    /**
     * Marshal a C++ string to Java.
     */
    static local_ref<jobject> marshal_string(JNIEnv *env, const std::string &str);

    /**
     * Marshal a Java string to C++.
     */
    static std::string marshal_string(JNIEnv *env, jstring str);

    /**
     * Marshal C++ std::optional<int32_t> to Java Integer.
     */
    local_ref<jobject> marshal_integer(JNIEnv *env, const std::optional<int32_t>& value);

    /**
     * Marshal a Java Integer to C++ std::optional<int32_t>.
     */
    std::optional<int32_t> marshal_integer(JNIEnv *env, jobject value);

    /**
     * Copy a uint8_view to a new Java byte array.
     */
    static local_ref<jbyteArray> marshal_uint8_view(JNIEnv *env, uint8_view v);

    /**
     * Add `o` to `collection`.
     * @return Whether successful.
     */
    bool collection_add(JNIEnv *env, jobject collection, jobject o);

    /**
     * @param enum_class The fully qualified name of a Java enum.
     * @return The enum's values.
     */
    std::vector<global_ref<jobject>> get_enum_values(JNIEnv *env, const std::string &enum_class);

    /**
     * @return The ordinal of the given enum value. See Javadoc for definition of ordinal.
     */
    jint get_enum_ordinal(JNIEnv *env, jobject enum_value);

};

}
