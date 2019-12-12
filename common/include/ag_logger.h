#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/sink.h>
#include <spdlog/fmt/bundled/format.h>
#include <spdlog/fmt/bundled/chrono.h>

namespace ag {

    using logger = std::shared_ptr<spdlog::logger>;
    using create_logger_cb = std::function<logger(const std::string &logger_name)>;

    enum log_level {
        TRACE = SPDLOG_LEVEL_TRACE,
        DEBUG = SPDLOG_LEVEL_DEBUG,
        INFO = SPDLOG_LEVEL_INFO,
        WARN = SPDLOG_LEVEL_WARN,
        ERR = SPDLOG_LEVEL_ERROR,
    };

    /**
     * @brief Create a logger with the given name
     * @param name logger name
     * @return logger instance
     */
    logger create_logger(const std::string &name);

    /**
     * @brief Set a program-wide logging level
     * @param lvl desired logging level
     */
    void set_default_log_level(log_level lvl);

    /**
     * @brief Set a function which produces the loggers
     * @param cb factory function
     */
    void set_logger_factory_callback(create_logger_cb cb);

} // namespace ag

#define errlog(l_, fmt_, ...) do { (l_)->error(FMT_STRING(fmt_), ##__VA_ARGS__); } while (0)
#define infolog(l_, fmt_, ...) do { (l_)->info(FMT_STRING(fmt_), ##__VA_ARGS__); } while (0)
#define warnlog(l_, fmt_, ...) do { (l_)->warn(FMT_STRING(fmt_), ##__VA_ARGS__); } while(0)
#define dbglog(l_, fmt_, ...) do { if ((l_)->should_log(spdlog::level::debug)) (l_)->debug(FMT_STRING(fmt_), ##__VA_ARGS__); } while (0)
#define tracelog(l_, fmt_, ...) do { if ((l_)->should_log(spdlog::level::trace)) (l_)->trace(FMT_STRING(fmt_), ##__VA_ARGS__); } while (0)
