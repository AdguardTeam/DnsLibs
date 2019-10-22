#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_sinks.h>

namespace ag {

using logger = std::shared_ptr<spdlog::logger>;

enum log_level {
    TRACE = SPDLOG_LEVEL_TRACE,
    DEBUG = SPDLOG_LEVEL_DEBUG,
    INFO = SPDLOG_LEVEL_INFO,
    WARN = SPDLOG_LEVEL_WARN,
    ERR = SPDLOG_LEVEL_ERROR,
};

    logger create_logger(const std::string &name);
    void set_default_log_level(log_level lvl);

} // namespace ag

#define errlog(l_, ...) do { (l_)->error(__VA_ARGS__); } while (0)
#define infolog(l_, ...) do { (l_)->info(__VA_ARGS__); } while (0)
#define warnlog(l_, ...) do { (l_)->warn(__VA_ARGS__); } while(0)
#define dbglog(l_, ...) do { if ((l_)->level() <= spdlog::level::debug) (l_)->debug(__VA_ARGS__); } while (0)
#define tracelog(l_, ...) do { if ((l_)->level() <= spdlog::level::trace) (l_)->trace(__VA_ARGS__); } while (0)
