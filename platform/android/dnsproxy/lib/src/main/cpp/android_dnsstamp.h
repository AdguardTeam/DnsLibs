#pragma once

#include "jni_utils.h"
#include <dns_stamp.h>

namespace ag {
    class android_dnsstamp {
        ag::jni_utils m_utils;
        std::vector<ag::global_ref<jobject>> m_dnsstamp_prototype_values;

    public:
        android_dnsstamp(JavaVM *vm);

        /**
         * Marshal DNS stamp from Java to C++
        */
        ag::server_stamp marshal_dnsstamp(JNIEnv *env, jobject java_dns_stamp);

        /**
         * Marshal DNS stamp from C++ to Java
         */
        local_ref<jobject> marshal_dnsstamp(JNIEnv *env, const ag::server_stamp &stamp);
    };
}
