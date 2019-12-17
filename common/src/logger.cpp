#include <ag_logger.h>
#include <spdlog/sinks/stdout_sinks.h>
#include <utility>

struct global_info {
    global_info() {
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%f] [%t] [%n] [%l] %v");
    }

    ag::log_level default_log_level = ag::INFO;
    ag::create_logger_cb create_logger_callback =
        [] (const std::string &name) { return spdlog::stdout_logger_mt(name); };
    std::mutex guard;
};

static global_info *get_globals() {
    static global_info info;
    return &info;
}


ag::logger ag::create_logger(const std::string &name) {
    global_info *info = get_globals();
    std::scoped_lock lock(info->guard);

    ag::logger logger = spdlog::get(name);
    if (logger == nullptr) {
        logger = info->create_logger_callback(name);
    }
    logger->set_level((spdlog::level::level_enum)info->default_log_level);
    return logger;
}

void ag::set_default_log_level(ag::log_level lvl) {
    global_info *info = get_globals();
    info->default_log_level = lvl;
}

void ag::set_logger_factory_callback(create_logger_cb cb) {
    global_info *info = get_globals();
    info->create_logger_callback = std::move(cb);
}
