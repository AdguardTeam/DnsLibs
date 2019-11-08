#include "event_loop.h"
#include <event2/event.h>
#include <event2/thread.h>

ag::event_loop::event_loop() : m_base() {
#ifndef _WIN32
    static const int ensure_threads [[maybe_unused]] = evthread_use_pthreads();
#else // _WIN32
    static const int ensure_threads [[maybe_unused]] = evthread_use_windows_threads();
    static const int ensure_sockets [[maybe_unused]] = WSAStartup(0x0202, std::array<WSADATA, 1>().data());
#endif // else of _WIN32

    m_base = event_base_new();
    evthread_make_base_notifiable(m_base);
    m_base_thread = new std::thread([this] { run(); });
}

ag::event_loop::~event_loop() {
    stop();
    m_base_thread->join();
    event_base_free(m_base);
    delete m_base_thread;
}

void ag::event_loop::stop() {
    event_base_loopexit(m_base, nullptr);
}

event_base *ag::event_loop::c_base() {
    return m_base;
}

void ag::event_loop::run() {
    event_base_loop(m_base, EVLOOP_NO_EXIT_ON_EMPTY);
}

ag::event_loop_ptr ag::event_loop::create() {
    return event_loop_ptr(new event_loop);
}
