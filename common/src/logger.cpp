#include <ag_logger.h>
#include <spdlog/sinks/stdout_sinks.h>

static ag::log_level default_log_level = ag::INFO;
static ag::create_logger_cb create_logger_callback =
    [] (const std::string &name) { return spdlog::stdout_logger_mt(name); };

struct pattern_inititlizer {
    pattern_inititlizer() {
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%f] [%t] [%n] [%l] %v");
    }
};

ag::logger ag::create_logger(const std::string &name) {
    static const pattern_inititlizer set_pattern;

    static std::mutex guard;
    std::scoped_lock lock(guard);

    ag::logger logger = spdlog::get(name);
    if (logger == nullptr) {
        logger = create_logger_callback(name);
    }
    logger->set_level((spdlog::level::level_enum)default_log_level);
    return logger;
}

void ag::set_default_log_level(ag::log_level lvl) {
    default_log_level = lvl;
}

void ag::set_logger_factory_callback(create_logger_cb cb) {
    create_logger_callback = cb;
}
