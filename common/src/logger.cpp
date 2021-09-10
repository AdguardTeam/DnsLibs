#include <ag_logger.h>
#include <utility>
#include <memory>
#include <atomic>

#include "spdlog/sinks/base_sink.h"

static void default_callback(ag::log_level, const char *message, size_t length) {
    fprintf(stderr, "%.*s", (int) length, message);
}

struct global_info {
    std::atomic<ag::log_level> default_log_level = ag::INFO;
    std::shared_ptr<ag::logger_cb> callback = std::make_shared<ag::logger_cb>(default_callback);

    global_info() {
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%f] [%t] [%n] [%l] %v");
    }
};

static global_info *get_globals() {
    static global_info info;
    return &info;
}

struct callback_sink : spdlog::sinks::base_sink<std::mutex> {
    void sink_it_(const spdlog::details::log_msg &msg) override {
        spdlog::memory_buf_t formatted;
        this->formatter_->format(msg, formatted);

        global_info *info = get_globals();
        std::shared_ptr<ag::logger_cb> callback = std::atomic_load(&info->callback);

        (*callback)((ag::log_level) msg.level, formatted.data(), formatted.size());
    }

    void flush_() override {
        // No op
    }
};

ag::logger ag::create_logger(const std::string &name) {
    static std::mutex spdlog_registry_mtx;
    std::scoped_lock l(spdlog_registry_mtx);
    ag::logger logger = spdlog::get(name);
    if (logger == nullptr) {
        logger = spdlog::default_factory::create<callback_sink>(name);
        logger->set_level((spdlog::level::level_enum) get_globals()->default_log_level.load());
    }
    return logger;
}

void ag::set_default_log_level(ag::log_level lvl) {
    global_info *info = get_globals();
    info->default_log_level.store(lvl);
    spdlog::set_level((spdlog::level::level_enum)lvl);
}

void ag::set_logger_callback(ag::logger_cb cb) {
    global_info *info = get_globals();
    std::atomic_store(&info->callback, std::make_shared<ag::logger_cb>(
            cb ? std::move(cb) : default_callback));
}
