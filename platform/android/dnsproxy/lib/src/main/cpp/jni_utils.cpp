#include <jni_utils.h>
#include <ag_utils.h>

/**
 * @return The length of a CESU-8 representation of the input UTF-8 string,
 * -1 if the input string is not dereferenceable.
 * @param utf8 The input string.
 */
static ssize_t cesu8_len(const char *utf8);

/**
 * Encode the given string to CESU-8 and append it to the output buffer.
 * @param utf8   The input string.
 * @param output The output buffer.
 */
static void utf8_to_cesu8(const char *utf8, std::string &output);

/**
 * Encode the given string to CESU-8.
 * @param utf8 The input string.
 * @return The CESU-8 representation of the input string.
 */
static std::string utf8_to_cesu8(const char *utf8);

void ag::jni_utils::iterate(JNIEnv *env,
                            jobject iterable,
                            const std::function<void(local_ref<jobject> &&)> &f) {

    auto iterable_class = m_jclasses.iterable.get();
    assert(env->IsInstanceOf(iterable, iterable_class));

    auto iterator_method = m_iterable_methods.iterator;
    auto has_next_method = m_iterator_methods.has_next;
    auto next_method = m_iterator_methods.next;

    auto it = env->CallObjectMethod(iterable, iterator_method);

    bool has_next;
    while ((has_next = env->CallBooleanMethod(it, has_next_method))) {
        local_ref next(env, env->CallObjectMethod(it, next_method));
        assert(!env->ExceptionCheck());
        f(std::move(next));
    }
}

void ag::jni_utils::visit_string(JNIEnv *env,
                                 jobject string,
                                 const std::function<void(const char *, jsize)> &f) {

    assert(env->IsInstanceOf(string, m_jclasses.string.get()));
    auto str = env->GetStringUTFChars((jstring) string, nullptr);
    auto len = env->GetStringUTFLength((jstring) string);
    f(str, len);
    env->ReleaseStringUTFChars((jstring) string, str);
}

ag::local_ref<jobject> ag::jni_utils::marshal_string(JNIEnv *env, const std::string &str) {
    if (str.empty()) {
        return local_ref<jobject>(env, env->NewStringUTF(""));
    }
    return local_ref<jobject>(env, env->NewStringUTF(utf8_to_cesu8(str.c_str()).c_str()));
}

bool ag::jni_utils::collection_add(JNIEnv *env, jobject collection, jobject o) {
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

ag::jni_utils::jni_utils(JNIEnv *env) {
    auto vm = get_vm(env);

    jclass c = (m_jclasses.collection = global_ref(vm, env->FindClass("java/util/Collection"))).get();
    m_collection_methods.add = env->GetMethodID(c, "add", "(Ljava/lang/Object;)Z");

    c = (m_jclasses.iterable = global_ref(vm, env->FindClass("java/lang/Iterable"))).get();
    m_iterable_methods.iterator = env->GetMethodID(c, "iterator", "()Ljava/util/Iterator;");

    c = (m_jclasses.iterator = global_ref(vm, env->FindClass("java/util/Iterator"))).get();
    m_iterator_methods.has_next = env->GetMethodID(c, "hasNext", "()Z");
    m_iterator_methods.next = env->GetMethodID(c, "next", "()Ljava/lang/Object;");

    c = (m_jclasses.enum_base = global_ref(vm, env->FindClass("java/lang/Enum"))).get();
    m_enum_methods.ordinal = env->GetMethodID(c, "ordinal", "()I");

    c = (m_jclasses.string = global_ref(vm, env->FindClass("java/lang/String"))).get();
}

std::vector<ag::global_ref<jobject>> ag::jni_utils::get_enum_values(JNIEnv *env, const std::string &enum_class) {
    assert(!enum_class.empty());

    auto clazz = env->FindClass(enum_class.c_str());
    assert(env->IsAssignableFrom(clazz, m_jclasses.enum_base.get()));

    std::vector<global_ref<jobject>> result;
    auto values_method = env->GetStaticMethodID(clazz, "values", AG_FMT("()[L{};", enum_class).c_str());
    if (local_ref values{env, env->CallStaticObjectMethod(clazz, values_method)}) {
        jsize len = env->GetArrayLength((jarray) values.get());
        for (int64_t i = 0; i < len; ++i) {
            local_ref e(env, env->GetObjectArrayElement((jobjectArray) values.get(), i));
            result.emplace_back(get_vm(env), e.get());
        }
    }

    return result;
}

jint ag::jni_utils::get_enum_ordinal(JNIEnv *env, jobject enum_value) {
    assert(env->IsInstanceOf(enum_value, m_jclasses.enum_base.get()));
    return env->CallIntMethod(enum_value, m_enum_methods.ordinal);
}

ag::local_ref<jbyteArray> ag::jni_utils::marshal_uint8_view(JNIEnv *env, ag::uint8_view v) {
    jint len = v.size();
    local_ref<jbyteArray> arr(env, env->NewByteArray(len));
    if (!v.empty()) {
        env->SetByteArrayRegion(arr.get(), 0, len, (jbyte *) v.data());
    }
    return arr;
}

std::string utf8_to_cesu8(const char *utf8) {
    if (!utf8) {
        return {};
    }
    auto modified_utf_len = cesu8_len(utf8);
    if (modified_utf_len < 0) {
        return {};
    }
    std::string modified_utf;
    modified_utf.reserve(modified_utf_len);
    utf8_to_cesu8(utf8, modified_utf);
    return modified_utf;
}

static ssize_t cesu8_len(const char *utf8) {
    if (!utf8) {
        return -1;
    }

    int current_char_len = 0;
    int utf_chars_remaining = 0;
    size_t i = 0;
    for (const auto *p = (const uint8_t *) utf8; *p; p++) {
        if (utf_chars_remaining > 0) {
            if ((*p & 0xc0) == 0x80) {
                current_char_len++;
                utf_chars_remaining--;
                if (utf_chars_remaining == 0) {
                    if (current_char_len == 4) {
                        current_char_len = 6;
                    }
                    i += current_char_len;
                }
                continue;
            } else {
                // replacement char
                i += 3;
                utf_chars_remaining = 0;
            }
        }

        if ((*p & 0x80) == 0x0) {
            i++;
        } else if ((*p & 0xe0) == 0xc0) {
            current_char_len = 1;
            utf_chars_remaining = 1;
        } else if ((*p & 0xf0) == 0xe0) {
            current_char_len = 1;
            utf_chars_remaining = 2;
        } else if ((*p & 0xf8) == 0xf0) {
            current_char_len = 1;
            utf_chars_remaining = 3;
        } else {
            // replacement char
            i += 3;
            utf_chars_remaining = 0;
        }
    }

    return i;
}

static void utf8_to_cesu8(const char *utf8, std::string &output) {
    int utf_chars_remaining = 0;
    int current_uchar = 0;
    auto &modified_utf = output;
    for (const auto *p = (const uint8_t *) utf8; *p; ++p) {
        if (utf_chars_remaining > 0) {
            if ((*p & 0xc0) == 0x80) {
                current_uchar <<= 6;
                current_uchar |= *p & 0x3f;
                utf_chars_remaining--;
                if (utf_chars_remaining == 0) {
                    if (current_uchar <= 0x7ff) {
                        modified_utf.push_back(0xc0 + ((current_uchar >> 6) & 0x1f));
                        modified_utf.push_back(0x80 + ((current_uchar) & 0x3f));
                    } else if (current_uchar <= 0xffff) {
                        modified_utf.push_back(0xe0 + ((current_uchar >> 12) & 0x0f));
                        modified_utf.push_back(0x80 + ((current_uchar >> 6) & 0x3f));
                        modified_utf.push_back(0x80 + ((current_uchar) & 0x3f));
                    } else { // (current_uchar <= 0x10ffff) is always true
                        // Split into CESU-8 surrogate pair
                        // uchar is 21 bit.
                        // 11101101 1010yyyy 10xxxxxx 11101101 1011xxxx 10xxxxxx
                        // yyyy - top five bits minus one

                        modified_utf.push_back(0xed);
                        modified_utf.push_back(0xa0 + (((current_uchar >> 16) - 1) & 0x0f));
                        modified_utf.push_back(0x80 + ((current_uchar >> 10) & 0x3f));

                        modified_utf.push_back(0xed);
                        modified_utf.push_back(0xb0 + ((current_uchar >> 6) & 0x0f));
                        modified_utf.push_back(0x80 + ((current_uchar >> 0) & 0x3f));
                    }
                }
                continue;
            } else {
                // replacement char
                modified_utf.push_back(0xef);
                modified_utf.push_back(0xbf);
                modified_utf.push_back(0xbd);
                utf_chars_remaining = 0;
            }
        }

        if ((*p & 0x80) == 0x0) {
            modified_utf.push_back(*p);
        } else if ((*p & 0xe0) == 0xc0) {
            current_uchar = *p & 0x1f;
            utf_chars_remaining = 1;
        } else if ((*p & 0xf0) == 0xe0) {
            current_uchar = *p & 0x0f;
            utf_chars_remaining = 2;
        } else if ((*p & 0xf8) == 0xf0) {
            current_uchar = *p & 0x07;
            utf_chars_remaining = 3;
        } else {
            // replacement char
            modified_utf.push_back(0xef);
            modified_utf.push_back(0xbf);
            modified_utf.push_back(0xbd);
            utf_chars_remaining = 0;
        }
    }
}
