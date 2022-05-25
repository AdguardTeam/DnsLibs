#include <cassert>

#include "common/cesu8.h"
#include "common/utils.h"

#include "jni_utils.h"

namespace ag::jni {

void JniUtils::iterate(JNIEnv *env, jobject iterable, const std::function<void(LocalRef<jobject> &&)> &f) {

    auto iterable_class = m_jclasses.iterable.get();
    assert(env->IsInstanceOf(iterable, iterable_class));

    auto iterator_method = m_iterable_methods.iterator;
    auto has_next_method = m_iterator_methods.has_next;
    auto next_method = m_iterator_methods.next;

    auto it = env->CallObjectMethod(iterable, iterator_method);

    bool has_next;
    while ((has_next = env->CallBooleanMethod(it, has_next_method))) {
        LocalRef next(env, env->CallObjectMethod(it, next_method));
        assert(!env->ExceptionCheck());
        f(std::move(next));
    }
}

void JniUtils::visit_string(JNIEnv *env, jobject string, const std::function<void(const char *, jsize)> &f) {
    auto str = env->GetStringUTFChars((jstring) string, nullptr);
    assert(str != nullptr);
    auto len = env->GetStringUTFLength((jstring) string);
    f(str, len);
    env->ReleaseStringUTFChars((jstring) string, str);
}

LocalRef<jstring> JniUtils::marshal_string(JNIEnv *env, std::string_view str) {
    if (str.empty()) {
        return LocalRef<jstring>(env, env->NewStringUTF(""));
    }
    return LocalRef<jstring>(env, env->NewStringUTF(ag::utf8_to_cesu8(str).c_str()));
}

std::string JniUtils::marshal_string(JNIEnv *env, jstring str) {
    std::string result;
    JniUtils::visit_string(env, str, [&result](const char *str, jsize len) {
        result.assign(str, len);
    });
    return result;
}

bool JniUtils::collection_add(JNIEnv *env, jobject collection, jobject o) {
    auto clazz = m_jclasses.collection.get();
    assert(env->IsInstanceOf(collection, clazz));

    auto add_method = m_collection_methods.add;

    auto ret = env->CallBooleanMethod(collection, add_method, o);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        ret = false;
    }
    return ret;
}

JniUtils::JniUtils(JavaVM *vm) {
    ScopedJniEnv env(vm, 16);

    jclass c = (m_jclasses.collection = GlobalRef(vm, env->FindClass("java/util/Collection"))).get();
    m_collection_methods.add = env->GetMethodID(c, "add", "(Ljava/lang/Object;)Z");

    c = (m_jclasses.iterable = GlobalRef(vm, env->FindClass("java/lang/Iterable"))).get();
    m_iterable_methods.iterator = env->GetMethodID(c, "iterator", "()Ljava/util/Iterator;");

    c = (m_jclasses.iterator = GlobalRef(vm, env->FindClass("java/util/Iterator"))).get();
    m_iterator_methods.has_next = env->GetMethodID(c, "hasNext", "()Z");
    m_iterator_methods.next = env->GetMethodID(c, "next", "()Ljava/lang/Object;");

    c = (m_jclasses.enum_base = GlobalRef(vm, env->FindClass("java/lang/Enum"))).get();
    m_enum_methods.ordinal = env->GetMethodID(c, "ordinal", "()I");

    c = (m_jclasses.string = GlobalRef(vm, env->FindClass("java/lang/String"))).get();

    c = (m_jclasses.integer = GlobalRef(vm, env->FindClass("java/lang/Integer"))).get();
    m_integer_methods.value_of = env->GetStaticMethodID(c, "valueOf", "(I)Ljava/lang/Integer;");
    m_integer_methods.int_value = env->GetMethodID(c, "intValue", "()I");
}

std::vector<GlobalRef<jobject>> JniUtils::get_enum_values(JNIEnv *env, const std::string &enum_class) {
    assert(!enum_class.empty());

    auto clazz = env->FindClass(enum_class.c_str());
    assert(env->IsAssignableFrom(clazz, m_jclasses.enum_base.get()));

    std::vector<GlobalRef<jobject>> result;
    auto values_method = env->GetStaticMethodID(clazz, "values", AG_FMT("()[L{};", enum_class).c_str());
    if (LocalRef values{env, env->CallStaticObjectMethod(clazz, values_method)}) {
        jsize len = env->GetArrayLength((jarray) values.get());
        for (int64_t i = 0; i < len; ++i) {
            LocalRef e(env, env->GetObjectArrayElement((jobjectArray) values.get(), i));
            result.emplace_back(get_vm(env), e.get());
        }
    }

    return result;
}

jint JniUtils::get_enum_ordinal(JNIEnv *env, jobject enum_value) {
    assert(env->IsInstanceOf(enum_value, m_jclasses.enum_base.get()));
    return env->CallIntMethod(enum_value, m_enum_methods.ordinal);
}

LocalRef<jbyteArray> JniUtils::marshal_uint8_view(JNIEnv *env, Uint8View v) {
    jint len = v.size();
    LocalRef<jbyteArray> arr(env, env->NewByteArray(len));
    if (!v.empty()) {
        env->SetByteArrayRegion(arr.get(), 0, len, (jbyte *) v.data());
    }
    return arr;
}

LocalRef<jobject> JniUtils::marshal_integer(JNIEnv *env, const std::optional<int32_t> &value) {
    return LocalRef<jobject>(env,
            value.has_value()
                    ? env->CallStaticObjectMethod(m_jclasses.integer.get(), m_integer_methods.value_of, (jint) *value)
                    : nullptr);
}

std::optional<int32_t> JniUtils::marshal_integer(JNIEnv *env, jobject value) {
    if (env->IsSameObject(value, nullptr)) {
        return std::nullopt;
    }
    return env->CallIntMethod(value, m_integer_methods.int_value);
}

} // namespace ag::jni
