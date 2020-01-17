#pragma once

#include <chrono>

namespace ag {

/**
 * Steady clock with time shifting.
 * Time shifting is not thread-safe and MUST ONLY be used for testing in controlled environments.
 */
class steady_clock : public std::chrono::steady_clock {
public:
    using base = std::chrono::steady_clock;

public:
    /**
     * Return (base::now() + get_time_shift()). Hides now() from base class.
     * @return the shifted time
     */
    static time_point now() noexcept {
        return base::now() + m_time_shift;
    }

    static duration get_time_shift() {
        return m_time_shift;
    }

    /**
     * WARNING: not thread-safe, intended only for testing
     */
    static void add_time_shift(duration value) {
        m_time_shift += value;
    }

    /**
     * WARNING: not thread-safe, intended only for testing
     */
    static void reset_time_shift() {
        m_time_shift = duration::zero();
    }

private:
    static duration m_time_shift;
};

} // namespace ag
