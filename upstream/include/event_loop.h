#pragma once

#include <memory>
#include <thread>

struct event_base;

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
     * Stop event loop
     */
    void stop();

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
    event_base *m_base;
    /** Thread where base loop is running */
    std::thread *m_base_thread;

    event_loop();

    /** Code for running base loop in thread */
    void run();
};

} // namespace ag
