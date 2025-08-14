#include <vector>
#include <uv.h>

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif // __APPLE__

#include "common/logger.h"
#include "common/time_utils.h"

#include "dns/common/event_loop.h"
#include "dns/common/uv_wrapper.h"

namespace ag::dns {

static constexpr int MAX_STOPPER_ITERATIONS = 10;

EventLoopPtr EventLoop::create() {
    auto loop = std::make_shared<EventLoop>(ConstructorAccess{});
    if (!loop->valid()) {
        loop.reset();
    }
    return loop;
}

EventLoop::EventLoop(const EventLoop::ConstructorAccess & /* access */)
        : m_log(__func__)
{
    m_handle = Uv<uv_loop_t>::create_with_parent(this);
    if (0 != uv_loop_init(m_handle->raw())) {
        m_handle.reset();
        return;
    }
    m_async = Uv<uv_async_t>::create_with_parent(this);
    uv_async_init(m_handle->raw(), m_async->raw(), [](uv_async_t *handle) {
        if (auto *self = static_cast<EventLoop *>(Uv<uv_async_t>::parent_from_data(handle->data))) {
            self->execute_async_tasks();
        }
    });
    m_timer = Uv<uv_timer_t>::create_with_parent(this);
    uv_timer_init(m_handle->raw(), m_timer->raw());
}

uv_loop_t *EventLoop::handle() {
    return m_handle->raw();
}

std::vector<uv_handle_t *> EventLoop::get_active_handles() {
    std::vector<uv_handle_t *> active_handles;
    walk([&active_handles, this](uv_handle_t *handle) {
        if (m_async && (void *) m_async->raw() == (void *) handle) {
            return;
        }
        if (m_timer && (void *) m_timer->raw() == (void *) handle) {
            return;
        }
        if (m_stopper && (void *) m_stopper->raw() == (void *) handle) {
            return;
        }
        if (!uv_is_closing(handle)) {
            active_handles.emplace_back(handle);
        }
    });
    return active_handles;
}

void EventLoop::force_fire_timers() {
    walk([this](uv_handle_t *handle){
        if (handle->type == UV_TIMER && uv_is_active(handle)) {
            auto *timer = (uv_timer_t *) handle;
            uv_timer_stop(timer);
            if (timer->timer_cb) {
                dbglog(m_log, "Force firing timer {}", (void *)timer);
                timer->timer_cb(timer);
            }
        }
    });
}

void EventLoop::execute_stopper_iteration() noexcept {
    this->force_fire_timers();
    this->execute_async_tasks();
    this->execute_timer_tasks();
    std::scoped_lock l(m_async_mutex, m_timer_mutex);
    std::vector<uv_handle_t *> active_handles = this->get_active_handles();
    if (m_async_queue.empty() && m_timer_queue.queue.empty()) {
        if (active_handles.empty()) {
            m_async.reset();
            m_timer.reset();
            m_stopper.reset();
            return;
        }
        warnlog(m_log, "Warning! Active handles exist on the event loop stop:");
        for (uv_handle_t *ah : active_handles) {
            warnlog(m_log, "{} {}", uv_handle_type_name(ah->type), (void *)ah);
        }
    }
    if (++m_stopping_cycle == MAX_STOPPER_ITERATIONS) {
        warnlog(m_log, "Event loop didn't stop after 10 iterations, aborting");
        abort();
    }
}

void EventLoop::stop() {
    m_stopping = true;
    submit([this]{
        m_stopper = Uv<uv_idle_t>::create_with_parent(this);
        uv_idle_init(m_handle->raw(), m_stopper->raw());
        uv_idle_start(m_stopper->raw(), [](uv_idle_t *idle) {
            if (auto *self = static_cast<EventLoop *>(Uv<uv_timer_t>::parent_from_data(idle->data))) {
                self->execute_stopper_iteration();
            }
        });
    });
}

void EventLoop::join() {
    dbglog(m_log, "Joining");
    if (m_thread.joinable()) {
        m_thread.join();
    }
    dbglog(m_log, "Joined");
}

void EventLoop::start(EventLoopSettings settings) {
    if (m_handle && !m_running) {
        m_running = true;
        m_thread = std::thread([this, settings = std::move(settings)]{
            (void)settings; // [[maybe_unused]] isn't supported on lambda captures
#ifndef _WIN32
            signal(SIGPIPE, SIG_IGN);
#ifdef __APPLE__
#if TARGET_OS_IPHONE
            pthread_set_qos_class_self_np(settings.qos_priority, 0);
#else
            pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0);
#endif // TARGET_OS_IPHONE
#endif // __APPLE__
#endif
            uv_run(m_handle->raw(), UV_RUN_DEFAULT);
            m_running = false;
            m_handle.reset();
        });
    }
}

EventLoop::~EventLoop() {
    dbglog(m_log, "Destroying");
    if (m_running && !m_stopping) {
        errlog(m_log, "Event loop was not stopped before destruction");
        abort();
    }
    join();
    dbglog(m_log, "Destroyed");
}

void EventLoop::execute_async_tasks() noexcept {
    if (std::unique_lock l(m_async_mutex); !m_async_queue.empty()) {
        std::list<std::function<void()>> tasks;
        tasks.splice(tasks.end(), m_async_queue, m_async_queue.begin());
        l.unlock();
        for (auto &&task : tasks) {
            task();
        }
        l.lock();
        if (!m_async_queue.empty()) {
            uv_async_send(m_async->raw());
        }
    }
}

EventLoop::TaskId EventLoop::schedule(Micros postpone_time, std::function<void()> task) {
    EventLoop::TaskId id;
    {
        std::scoped_lock l(m_timer_mutex);
        id = ++m_timer_queue.task_id_counter;
        m_timer_queue.queue.emplace(SteadyClock::now() + postpone_time, PostponedTasks::Task{
                .task_id = id,
                .func = std::move(task)
        });
    }
    submit([this]{
        update_timer();
    });
    return id;
}

std::function<void()> EventLoop::pop_timer_task(SteadyClock::time_point before) {
    std::function<void()> ret = nullptr;
    std::scoped_lock l(m_timer_mutex);
    if (m_timer_queue.queue.empty()) {
        return ret;
    }
    if (auto it = m_timer_queue.queue.begin(); it->first <= before || m_stopping) {
        ret = std::move(it->second.func);
        m_timer_queue.queue.erase(it);
    }
    return ret;
}

void EventLoop::execute_timer_tasks() noexcept {
    auto now = SteadyClock::now();
    tracelog(m_log, "Starting executing scheduled tasks");
    int count = 0;
    for (;;) {
        std::function<void()> f = pop_timer_task(now);
        if (!f) {
            break;
        }
        f();
        count++;
    }
    tracelog(m_log, "Executed {} scheduled tasks", count);
    update_timer();
}

void EventLoop::cancel(TaskId id) {
    std::scoped_lock l(m_timer_mutex);
    for (auto it = m_timer_queue.queue.begin(); it != m_timer_queue.queue.end();) {
        if (it->second.task_id == id) {
            it = m_timer_queue.queue.erase(it);
        } else {
            it++;
        }
    }
}

void EventLoop::update_timer() {
    std::scoped_lock l(m_timer_mutex);
    if (m_timer == nullptr) {
        // timer already stopped
        return;
    }
    if (auto begin = m_timer_queue.queue.begin(); begin != m_timer_queue.queue.end()) {
        auto timeout = std::max(Millis{0}, std::chrono::ceil<Millis>(begin->first - SteadyClock::now()));
        tracelog(m_log, "Scheduled next task in {}", timeout);
        uv_timer_start(m_timer->raw(), [](uv_timer_t *timer){
            if (auto *self = static_cast<EventLoop *>(Uv<uv_timer_t>::parent_from_data(timer->data))) {
                self->execute_timer_tasks();
            }
        }, timeout.count(), 0);
    } else {
        uv_timer_stop(m_timer->raw());
    }
}

} // namespace ag::dns
