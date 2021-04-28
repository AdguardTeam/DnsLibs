#pragma once

#include <memory>
#include <thread>
#include <functional>
#include <list>
#include <mutex>
#include <event2/event.h>
#include <ag_defs.h>


namespace ag {

class event_loop;
using event_loop_ptr = std::unique_ptr<event_loop>;

/**
 * Event loop class. Uses libevent.
 */
class event_loop {
public:
    /**
     * @return New event loop
     */
    static event_loop_ptr create();

    ~event_loop();

    /**
     * Submit a task to be executed on the event loop
     */
    void submit(std::function<void()> task);

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
    std::unique_ptr<event_base, ftor<&event_base_free>> m_base;
    /** Thread where base loop is running */
    std::thread m_base_thread;

    struct tasks {
        bool scheduled = false;
        std::list<std::function<void()>> queue;
    };
    /** Submitted tasks */
    with_mtx<tasks> m_tasks;

    event_loop();

    /** Code for running base loop in thread */
    void run();

    void execute_tasks();
};

} // namespace ag
