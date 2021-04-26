#include <ag_event_loop.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <array>
#include <ag_logger.h>
#include <csignal>

static ag::logger event_logger = ag::create_logger("LIBEVENT");
static const struct event_log_cb_setter {
    event_log_cb_setter() noexcept {
        event_set_log_callback([](int severity, const char *msg) {
            switch (severity) {
            case EVENT_LOG_DEBUG:
                dbglog(event_logger, "{}", msg);
                break;
            case EVENT_LOG_MSG:
                infolog(event_logger, "{}", msg);
                break;
            case EVENT_LOG_WARN:
                warnlog(event_logger, "{}", msg);
                break;
            case EVENT_LOG_ERR:
                errlog(event_logger, "{}", msg);
                break;
            default:
                tracelog(event_logger, "???: {}", msg);
            }
        });
    }
} set_event_log_cb [[maybe_unused]];

ag::event_loop::event_loop() : m_base() {
#ifndef _WIN32
    static const int ensure_threads [[maybe_unused]] = evthread_use_pthreads();
#else // _WIN32
    static const int ensure_threads [[maybe_unused]] = evthread_use_windows_threads();
    static const int ensure_sockets [[maybe_unused]] = WSAStartup(0x0202, std::array<WSADATA, 1>().data());
#endif // else of _WIN32

    m_base.reset(event_base_new());
    assert(m_base);
    evthread_make_base_notifiable(m_base.get());
    m_base_thread = std::thread([this] { run(); });
}

ag::event_loop::~event_loop() {
    stop();
    join();
    m_base.reset();
}

void ag::event_loop::submit(std::function<void()> func) {
    std::scoped_lock l(m_tasks.mtx);
    m_tasks.val.queue.emplace_back(std::move(func));

    if (!m_tasks.val.scheduled) {
        event_base_once(m_base.get(), -1, EV_TIMEOUT,
                [] (evutil_socket_t, short, void *arg) {
                    auto *self = (event_loop *)arg;

                    do {
                        std::function<void()> task;
                        {
                            std::scoped_lock l(self->m_tasks.mtx);
                            if (self->m_tasks.val.queue.empty()) {
                                self->m_tasks.val.scheduled = false;
                                break;
                            }
                            task = std::move(self->m_tasks.val.queue.front());
                            self->m_tasks.val.queue.pop_front();
                        }
                        task();
                    } while (true);
                },
                this, nullptr);
    }
}

void ag::event_loop::stop() {
    event_base_loopexit(m_base.get(), nullptr);
}

void ag::event_loop::join() {
    if (m_base_thread.joinable()) {
        m_base_thread.join();
    }

    std::scoped_lock l(m_tasks.mtx);
    while (!m_tasks.val.queue.empty()) {
        m_tasks.val.queue.front()();
        m_tasks.val.queue.pop_front();
    }
}

event_base *ag::event_loop::c_base() {
    return m_base.get();
}

void ag::event_loop::run() {
#ifdef __MACH__
    static auto ensure_sigpipe_ignored [[maybe_unused]] = signal(SIGPIPE, SIG_IGN);

#elif defined EVTHREAD_USE_PTHREADS_IMPLEMENTED
    // Block SIGPIPE
    sigset_t sigset, oldset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &sigset, &oldset);
#endif // EVTHREAD_USE_PTHREADS_IMPLEMENTED

    event_base_loop(m_base.get(), EVLOOP_NO_EXIT_ON_EMPTY);

#if defined(EVTHREAD_USE_PTHREADS_IMPLEMENTED) && !defined(__MACH__)
    // Restore SIGPIPE state
    pthread_sigmask(SIG_SETMASK, &oldset, nullptr);
#endif
}

ag::event_loop_ptr ag::event_loop::create() {
    return event_loop_ptr(new event_loop);
}
