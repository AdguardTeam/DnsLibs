#pragma once

#include <chrono>
#include <concepts>
#include <future>
#include <list>
#include <map>
#include <memory>
#include <thread>

#include "common/clock.h"
#include "common/coro.h"
#include "common/defs.h"
#include "common/logger.h"
#include "dns/common/uv_wrapper.h"

namespace ag::dns {

class EventLoop;

using EventLoopPtr = std::shared_ptr<EventLoop>;

/**
 * Event loop class. Uses libuv.
 * This class is not thread-safe, it should be accessed only before loop start and inside loop.
 */
class EventLoop : public std::enable_shared_from_this<EventLoop> {
    struct ConstructorAccess { };
public:
    static EventLoopPtr create();

    explicit EventLoop(const ConstructorAccess &access);

    ~EventLoop();

    void start();
    void stop();
    void join();

    uv_loop_t *handle();

    template <typename T>
    using PromisePtr = std::shared_ptr<std::promise<T>>;

    /**
     * Execute code asynchronously on the event loop
     * @param func Function to execute
     */
    void submit(std::function<void()> &&func) {
        std::scoped_lock l(m_async_mutex);
        if (m_async == nullptr) {
            warnlog(m_log, "Attempted to submit on already stopped event loop");
            abort();
        }
        m_async_queue.emplace_back(std::move(func));
        uv_async_send(m_async->raw());
    }

    class TaskId {
    private:
        uint64_t value = 0;
    public:
        friend bool operator==(const TaskId &l, const TaskId &r) { return l.value == r.value; }
        TaskId &operator++() { ++value; return *this; }
    };

    struct PostponedTasks {
        struct Task {
            TaskId task_id;
            std::function<void()> func;
        };

        TaskId task_id_counter;
        std::multimap<SteadyClock::time_point, Task> queue;
    };

    /**
     * Schedule a `task` to be executed on the event loop after the `postpone_time`
     * @return task id
     */
    TaskId schedule(Micros postpone_time, std::function<void()> task);

    /**
     * Cancel execution of task (doesn't interrupt already executing task)
     */
    void cancel(TaskId id);

    /**
     * Submit asynchronous function to the event loop
     * @tparam T Returned future underlying type
     * @param async_func Function which takes promise with T as argument
     * @return Future of T. Async function is responsible for completing promise of this future
     */
    template <typename T>
    std::future<T> async(std::function<void(std::shared_ptr<std::promise<T>>)> &&async_func) {
        auto ptr = std::make_shared<std::promise<T>>();
        submit([ptr, async_func = std::move(async_func)] {
            async_func(ptr);
        });
        return ptr->get_future();
    }

    /**
     * Submit synchronous void function to the event loop
     * @param func Synchronous void function
     * @return Future which will be completed when function completes execution on the event loop
     */
    std::future<void> async(std::function<void()> &&func) {
        return async<void>([func = std::move(func)](PromisePtr<void> promise){
            func();
            promise->set_value();
        });
    }

    /**
     * Submits synchronous function to the event loop
     * @tparam T Returned future underlying type
     * @param func Synchronous function which returns the instance of type T
     * @return Future of T
     */
    template <typename T>
    std::future<T> async(std::function<T()> &&func) {
        return async<T>([func = std::move(func)](PromisePtr<T> promise){
            promise->set_value(func());
        });
    }

    /**
     * Co-routine helper used for invoking code after suspension point inside the event loop.
     */
    [[nodiscard]] auto co_submit() {
        struct Awaitable : public std::suspend_always {
            EventLoop *loop;
            void await_suspend(std::coroutine_handle<> h) {
                loop->submit(h);
            }
        };
        return Awaitable{.loop = this};
    }

    [[nodiscard]] auto co_sleep(Micros time) {
        struct Awaitable : public std::suspend_always {
            Micros time;
            EventLoop *loop;
            void await_suspend(std::coroutine_handle<> h) {
                loop->schedule(time, h);
            }
        };
        return Awaitable{.time = time, .loop = this};
    }

    [[nodiscard]] bool valid() { return m_handle != nullptr; }

private:
    ag::Logger m_log;
    UvPtr<uv_loop_t> m_handle;
    std::thread m_thread;
    std::atomic_bool m_running{false};

    std::mutex m_async_mutex;
    UvPtr<uv_async_t> m_async;
    std::list<std::function<void()>> m_async_queue;

    std::mutex m_timer_mutex;
    UvPtr<uv_timer_t> m_timer;
    PostponedTasks m_timer_queue;

    std::atomic_bool m_stopping{false};
    int m_stopping_cycle = 0;
    UvPtr<uv_idle_t> m_stopper;

    void execute_async_tasks() noexcept;
    void update_timer();
    std::function<void()> pop_timer_task(SteadyClock::time_point before);
    void execute_timer_tasks() noexcept;
    void execute_stopper_iteration() noexcept;
    std::vector<uv_handle_t *> get_active_handles();
    void force_fire_timers();

    template <typename Func>
    requires std::invocable<Func &, uv_handle_t *>
    void walk(Func func) {
        auto walker = [](uv_handle_t *handle, void *arg) {
            auto *callback = (Func *) arg;
            (*callback)(handle);
        };
        uv_walk(m_handle->raw(), walker, &func);
    }
};

} // namespace ag::dns
