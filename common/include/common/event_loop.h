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

class EventLoop;
using EventLoopPtr = std::unique_ptr<EventLoop>;

/**
 * Event loop class. Uses libevent.
 */
class EventLoop {
public:
    /**
     * @param run_immediately if true the loop will be `start`ed immediately
     * @return New event loop
     */
    static EventLoopPtr create(bool run_immediately = true);

    ~EventLoop();

    /**
     * Run event loop
     */
    void start();

    /**
     * Submit a task to be executed on the event loop
     */
    void submit(std::function<void()> task);

    class TaskId {
    private:
        uint64_t value = 0;
    public:
        friend bool operator==(const TaskId &l, const TaskId &r) { return l.value == r.value; }
        TaskId &operator++() { ++value; return *this; }
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
    EventLoop(const EventLoop &) = delete;
    EventLoop &operator=(const EventLoop &) = delete;
    EventLoop(EventLoop &&) = delete;
    EventLoop &operator=(EventLoop &&) = delete;

private:
    /** Libevent base */
    UniquePtr<event_base, &event_base_free> m_base;
    /** Thread where base loop is running */
    std::thread m_base_thread;

    struct Tasks {
        bool scheduled = false;
        std::list<std::function<void()>> queue;
    };
    /** Submitted tasks */
    WithMtx<Tasks> m_tasks;

    struct PostponedTasks {
        struct Task {
            EventLoop *event_loop;
            TaskId id;
            std::function<void()> func;
        };

        TaskId task_id_counter;
        std::list<Task> queue;
    };
    /** Postponed tasks */
    WithMtx<PostponedTasks> m_postponed_tasks;

    explicit EventLoop(bool run_immediately);

    /** Code for running base loop in thread */
    void run();

    void execute_tasks();

    static void run_tasks_queue(int, short, void *);
    static void run_postponed_task(int, short, void *);
};

} // namespace ag
