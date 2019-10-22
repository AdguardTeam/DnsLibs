#include <ag_logger.h>

static ag::log_level default_log_level = ag::INFO;

ag::logger ag::create_logger(const std::string &name) {
    ag::logger logger = spdlog::get(name);
    if (logger == nullptr) {
        logger = spdlog::stdout_logger_mt(name);
    }
    logger->set_level((spdlog::level::level_enum)default_log_level);
    return logger;
}

void ag::set_default_log_level(ag::log_level lvl) {
    default_log_level = lvl;
}
