#pragma once

#include <stdint.h>

namespace ag {

struct DeferredArg {
    static void *create(void *ptr);

    static void *to_ptr(void *deferred_arg);

    static void destroy(void *deferred_arg);

    class Guard {
    public:
        explicit Guard(void *value) {
            m_id = create(value);
        }

        ~Guard() {
            destroy(m_id);
        }

        void *value() {
            return (void *)m_id;
        }

    private:
        void *m_id;
    };
};

} // namespace ag
