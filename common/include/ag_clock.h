#pragma once

#include <chrono>
#include <utility>
#include <optional>


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

template<class T, T defaultValue>
class expiring_value {
public:
    using Duration = std::chrono::nanoseconds;

    expiring_value(T v, Duration d)
        : value(std::move(v))
        , expireTimestamp(steady_clock::now() + d)
        , duration(d)
    {}

    explicit expiring_value(Duration d)
        : value(defaultValue)
        , duration(d)
    {}

    expiring_value()
        : value(defaultValue)
    {}

    expiring_value(const expiring_value &other) = default;
    expiring_value &operator=(const expiring_value &other) = default;
    expiring_value(expiring_value &&other) = default;
    expiring_value &operator=(expiring_value &&other) = default;

    expiring_value &operator=(T v) {
        this->value = std::move(v);
        this->expireTimestamp = steady_clock::now() + this->duration;
        return *this;
    }

    [[nodiscard]] bool is_timed_out() const {
        return this->expireTimestamp.has_value()
                && steady_clock::now() > this->expireTimestamp.value();
    }

    const T &get() const {
        if (this->is_timed_out()) {
            this->value = defaultValue;
            this->expireTimestamp.reset();
        }
        return this->value;
    }

    void reset() {
        this->value = defaultValue;
        this->expireTimestamp.reset();
    }

private:
    mutable T value = {};
    mutable std::optional<steady_clock::time_point> expireTimestamp;
    Duration duration = {};
};

} // namespace ag
