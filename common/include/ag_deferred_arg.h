#pragma once

#include <stdint.h>

namespace ag {

void *deferred_arg_create(void *ptr);

void *deferred_arg_to_ptr(void *deferred_arg);

void deferred_arg_free(void *deferred_arg);

template<class T>
class enable_deferred_arg {
public:
    enable_deferred_arg() {
        m_id = deferred_arg_create(static_cast<T *>(this));
    }

    ~enable_deferred_arg() {
        deferred_arg_free(m_id);
    }

    void *deferred_arg() {
        return (void *)m_id;
    }

private:
    void *m_id;
};

} // namespace ag
