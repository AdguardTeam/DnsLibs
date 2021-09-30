#pragma once

#include <stdint.h>

namespace ag {

void *deferred_arg_create(void *ptr);

void *deferred_arg_to_ptr(void *deferred_arg);

void deferred_arg_free(void *deferred_arg);

class deferred_arg_guard {
public:
    explicit deferred_arg_guard(void *value) {
        m_id = deferred_arg_create(value);
    }

    ~deferred_arg_guard() {
        deferred_arg_free(m_id);
    }

    void *value() {
        return (void *)m_id;
    }

private:
    void *m_id;
};

} // namespace ag
