#include <ag_deferred_arg.h>
#include <map>
#include <mutex>

static std::mutex g_mutex;
static intptr_t next_id = 1;
static std::map<void *, void *> g_deferred_arg_to_ptr;

void *ag::deferred_arg_create(void *ptr) {
    std::scoped_lock l(g_mutex);
    void *id = (void *)next_id++;
    g_deferred_arg_to_ptr[id] = ptr;
    return id;
}

void ag::deferred_arg_free(void *deferred_arg) {
    std::scoped_lock l(g_mutex);
    g_deferred_arg_to_ptr.erase(deferred_arg);
}

void *ag::deferred_arg_to_ptr(void *deferred_arg) {
    std::scoped_lock l(g_mutex);
    if (auto it = g_deferred_arg_to_ptr.find(deferred_arg); it != g_deferred_arg_to_ptr.end()) {
        return it->second;
    }
    return nullptr;
}
