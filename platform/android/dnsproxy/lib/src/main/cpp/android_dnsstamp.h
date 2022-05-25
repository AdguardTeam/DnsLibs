#pragma once

#include "jni_utils.h"
#include "dnsstamp/dns_stamp.h"

namespace ag {
    class AndroidDnsStamp {
        jni::JniUtils m_utils;
        std::vector<jni::GlobalRef<jobject>> m_dnsstamp_prototype_values;

    public:
        AndroidDnsStamp(JavaVM *vm);

        /**
         * Marshal DNS stamp from Java to C++
        */
        ServerStamp marshal_dnsstamp(JNIEnv *env, jobject java_dns_stamp);

        /**
         * Marshal DNS stamp from C++ to Java
         */
        jni::LocalRef<jobject> marshal_dnsstamp(JNIEnv *env, const ServerStamp &stamp);
    };
}
