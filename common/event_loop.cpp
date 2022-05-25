#include <array>
#include <cassert>
#include <csignal>
#include <event2/event.h>
#include <event2/thread.h>

#include "common/event_loop.h"
#include "common/logger.h"
#include "common/time_utils.h"

namespace ag {

static Logger g_event_logger{"LIBEVENT"};
static const struct EventLogCbSetter {
    EventLogCbSetter() noexcept {
        event_set_log_callback([](int severity, const char *msg) {
            switch (severity) {
            case EVENT_LOG_DEBUG:
                dbglog(g_event_logger, "{}", msg);
                break;
            case EVENT_LOG_MSG:
                infolog(g_event_logger, "{}", msg);
                break;
            case EVENT_LOG_WARN:
                warnlog(g_event_logger, "{}", msg);
                break;
            case EVENT_LOG_ERR:
                errlog(g_event_logger, "{}", msg);
                break;
            default:
                tracelog(g_event_logger, "???: {}", msg);
            }
        });
    }
} g_set_event_log_cb [[maybe_unused]];

extern "C" struct evthread_lock_callbacks *evthread_get_lock_callbacks(void);

EventLoop::EventLoop(bool run_immediately) {
    // Check if `evthread_use_*()` was called before, because calling it twice leads to
    // program termination in case Libevent's debugging checks are enabled
    if (evthread_get_lock_callbacks()->lock == nullptr) {
#ifndef _WIN32
        static const int ensure_threads [[maybe_unused]] = evthread_use_pthreads();
#else // _WIN32
        static const int ensure_threads [[maybe_unused]] = evthread_use_windows_threads();
        static const int ensure_sockets [[maybe_unused]] = WSAStartup(0x0202, std::array<WSADATA, 1>().data());
#endif // else of _WIN32
    }

    m_base.reset(event_base_new());
    assert(m_base);
    evthread_make_base_notifiable(m_base.get());

    if (run_immediately) {
        start();
    }
}

EventLoop::~EventLoop() {
    stop();
    join();
    m_base.reset();
}

void EventLoop::start() {
    assert(!m_base_thread.joinable());
    this->join();

    m_base_thread = std::thread([this] {
        run();
    });
}

void EventLoop::run_tasks_queue(evutil_socket_t, short, void *arg) {
    auto *self = (EventLoop *) arg;
    self->execute_tasks();
}

void EventLoop::run_postponed_task(evutil_socket_t, short, void *arg) {
    auto *task_arg = (PostponedTasks::Task *) arg;
    EventLoop *self = task_arg->event_loop;

    std::optional<PostponedTasks::Task> task;
    {
        std::scoped_lock l(self->m_postponed_tasks.mtx);
        auto it = std::find_if(self->m_postponed_tasks.val.queue.begin(), self->m_postponed_tasks.val.queue.end(),
                [task_id = task_arg->id](const PostponedTasks::Task &i) -> bool {
                    return i.id == task_id;
                });
        if (it != self->m_postponed_tasks.val.queue.end()) {
            task = std::move(*it);
            self->m_postponed_tasks.val.queue.erase(it);
        }
    }

    if (task.has_value() && task->func) {
        task->func();
    }
}

void EventLoop::submit(std::function<void()> func) {
    std::scoped_lock l(m_tasks.mtx);
    m_tasks.val.queue.emplace_back(std::move(func));

    if (!m_tasks.val.scheduled) {
        event_base_once(m_base.get(), -1, EV_TIMEOUT, run_tasks_queue, this, nullptr);
    }
}

EventLoop::TaskId EventLoop::schedule(Micros postpone_time, std::function<void()> func) {
    std::scoped_lock l(m_postponed_tasks.mtx);
    auto &task = m_postponed_tasks.val.queue.emplace_back(
            PostponedTasks::Task{this, ++m_postponed_tasks.val.task_id_counter, std::move(func)});

    timeval tv = ag::duration_to_timeval(postpone_time);
    event_base_once(m_base.get(), -1, EV_TIMEOUT, run_postponed_task, &task, &tv);

    return task.id;
}

void EventLoop::cancel(TaskId id) {
    if (id == TaskId{}) {
        return;
    }
    std::scoped_lock l(m_postponed_tasks.mtx);
    auto it = std::find_if(m_postponed_tasks.val.queue.begin(), m_postponed_tasks.val.queue.end(),
            [id](const PostponedTasks::Task &i) -> bool {
                return i.id == id;
            });
    if (it != m_postponed_tasks.val.queue.end()) {
        it->func = nullptr;
    }
}

void EventLoop::stop() {
    event_base_loopexit(m_base.get(), nullptr);
}

void EventLoop::join() {
    if (m_base_thread.joinable()) {
        m_base_thread.join();
    }
}

event_base *EventLoop::c_base() {
    return m_base.get();
}

void EventLoop::run() {
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

    execute_tasks();
}

void EventLoop::execute_tasks() {
    size_t left;
    {
        std::scoped_lock l(m_tasks.mtx);
        // This should be reworked to ids if there will be cancellable tasks.
        left = m_tasks.val.queue.size();
    }
    do {
        std::function<void()> task;
        {
            std::scoped_lock l(m_tasks.mtx);
            if (m_tasks.val.queue.empty()) {
                m_tasks.val.scheduled = false;
                break;
            } else if (left == 0) {
                event_base_once(m_base.get(), -1, EV_TIMEOUT, run_tasks_queue, this, nullptr);
                break;
            }
            task = std::move(m_tasks.val.queue.front());
            m_tasks.val.queue.pop_front();
            left--;
        }
        task();
    } while (true);
}

EventLoopPtr EventLoop::create(bool run_immediately) {
    return EventLoopPtr(new EventLoop(run_immediately));
}

} // namespace ag
