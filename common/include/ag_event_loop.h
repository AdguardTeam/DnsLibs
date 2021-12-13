#pragma once

#include <memory>
#include <thread>
#include <functional>
#include <list>
#include <mutex>
#include <chrono>
#include <event2/event.h>
#include "common/defs.h"


namespace ag {

class event_loop;
using event_loop_ptr = std::unique_ptr<event_loop>;

/**
 * Event loop class. Uses libevent.
 */
class event_loop {
public:
    /**
     * @param run_immediately if true the loop will be `start`ed immediately
     * @return New event loop
     */
    static event_loop_ptr create(bool run_immediately = true);

    ~event_loop();

    /**
     * Run event loop
     */
    void start();

    /**
     * Submit a task to be executed on the event loop
     */
    void submit(std::function<void()> task);

    class task_id {
    private:
        uint64_t value = 0;
    public:
        friend bool operator==(const task_id &l, const task_id &r) { return l.value == r.value; }
        task_id &operator++() { ++value; return *this; }
    };

    /**
     * Schedule a `task` to be executed on the event loop after the `postpone_time`
     * @return task id
     */
    task_id schedule(std::chrono::microseconds postpone_time, std::function<void()> task);

    /**
     * Cancel execution of task (doesn't interrupt already executing task)
     */
    void cancel(task_id id);

    /**
     * Stop event loop
     */
    void stop();

    /**
     * Join event loop thread
     */
    void join();

    /**
     * @return Libevent base
     */
    event_base *c_base();

    // Copy is prohibited
    event_loop(const event_loop &) = delete;
    event_loop &operator=(const event_loop &) = delete;
    event_loop(event_loop &&) = delete;
    event_loop &operator=(event_loop &&) = delete;

private:
    /** Libevent base */
    std::unique_ptr<event_base, Ftor<&event_base_free>> m_base;
    /** Thread where base loop is running */
    std::thread m_base_thread;

    struct tasks {
        bool scheduled = false;
        std::list<std::function<void()>> queue;
    };
    /** Submitted tasks */
    WithMtx<tasks> m_tasks;

    struct postponed_tasks {
        struct task {
            event_loop *event_loop;
            task_id id;
            std::function<void()> func;
        };

        task_id task_id_counter;
        std::list<task> queue;
    };
    /** Postponed tasks */
    WithMtx<postponed_tasks> m_postponed_tasks;

    explicit event_loop(bool run_immediately);

    /** Code for running base loop in thread */
    void run();

    void execute_tasks();

    static void run_tasks_queue(int, short, void *);
    static void run_postponed_task(int, short, void *);
};

} // namespace ag
