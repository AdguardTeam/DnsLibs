#pragma once

#include <uv.h>
#include <memory>
#include <string>

#include "common/logger.h"
#include "common/utils.h"

namespace ag::dns {

template <typename UvT>
class Uv : public std::enable_shared_from_this<Uv<UvT>> {
protected:
    struct ConstructorAccess {
    };
public:
    Uv(const ConstructorAccess & /*unused*/, void *parent)
            : m_log(logger_name()),
              m_handle(new UvT{}),
              m_parent(parent) {
        dbglog(m_log, "Created {}, handle {}", (void *) this, (void *) m_handle);
    }

    static std::string logger_name() {
        static constexpr auto RADIX = 10;
        static constexpr std::string_view STRUCT_PREFIX = "struct ";

        char *pos = nullptr;
        (void) strtoll(typeid(UvT).name(), &pos, RADIX);
        std::string_view name = pos;
        if (name.starts_with(STRUCT_PREFIX)) {
            name.remove_prefix(STRUCT_PREFIX.size());
        }
        return AG_FMT("Uv<{}>", name);
    }
    static std::shared_ptr<Uv> create_with_parent(void *parent) {
        auto uv = std::make_shared<Uv>(ConstructorAccess{}, parent);
        uv->raw()->data = new std::weak_ptr<Uv<UvT>>(uv);
        return uv;
    }

    static void *parent_from_data(void *data) {
        return parent_from_weak(weak_from_data(data));
    }

    static void *parent_from_weak(std::weak_ptr<Uv> *weak) {
        auto ptr = weak->lock();
        return ptr ? ptr->parent() : nullptr;
    }

    static std::weak_ptr<Uv> *weak_from_data(void *data) {
        return (std::weak_ptr<Uv> *) data;
    }

    void *parent() {
        return m_parent;
    }

    [[nodiscard]] UvT *raw() {
        return m_handle;
    }

    [[nodiscard]] UvT *operator->() {
        return m_handle;
    }

    ~Uv() {
        dbglog(m_log, "Closing {} handle {}", (void *) this, (void *) m_handle);
        delete weak_from_data(m_handle->data);
        m_handle->data = nullptr;
        if constexpr (std::is_same_v<std::remove_cvref_t<UvT>, uv_loop_t>) {
            if (((uv_loop_t *) m_handle)->time != 0) {
                uv_loop_close((uv_loop_t *) m_handle);
            }
            delete m_handle;
        } else {
            if (m_handle->type == UV_UNKNOWN_HANDLE) {
                delete m_handle;
                return;
            }
            uv_close((uv_handle_t *) m_handle, Uv::on_close);
        }
    }

    static void on_close(uv_handle_t *handle) {
        Logger log(logger_name());
        dbglog(log, "Destroyed handle {}", (void *)handle);
        delete (UvT *) handle;
    }

private:
    Logger m_log;
    UvT *m_handle;
    void *m_parent;
};

/**
 * UvPtr is supposed to be used inside classes to store libuv related stuff
 */
template <typename UvT>
using UvPtr = std::shared_ptr<Uv<UvT>>;
/**
 * UvWeak is supposed to be used as callback argument
 */
template <typename UvT>
using UvWeak = std::weak_ptr<Uv<UvT>>;

} // namespace ag::dns
