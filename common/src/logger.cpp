#include <ag_logger.h>
#include <utility>
#include <memory>
#include <atomic>
#include <cassert>
#include <cinttypes>
#include <time.h>
#include <magic_enum.hpp>

#include "spdlog/sinks/base_sink.h"


#ifdef _WIN32
#include <windows.h>
#include <processthreadsapi.h>
#define gettid() GetCurrentThreadId()
#endif // _WIN32

#ifdef __MACH__
#include <pthread.h>
static inline pid_t gettid(void) {
    uint64_t tid;
    if (0 != pthread_threadid_np(NULL, &tid))
        return 0;
    return (pid_t)tid;
}
#endif // __MACH__

#ifdef __linux__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>

#ifdef ANDROID
#include <pthread.h>
#else
#include <sys/syscall.h>
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
static inline pid_t gettid(void) {
    return syscall(SYS_gettid);
}
#endif // __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#endif //ANDROID
#endif // __linux__


static void default_callback(ag::log_level lvl, const char *message, size_t length) {
    using namespace std::chrono;

    system_clock::time_point now = system_clock::now();
    std::time_t time = system_clock::to_time_t(now);

    tm tm = {};
#ifdef _WIN32
    if (localtime_s(&tm, &time) != 0) {
        tm = {}; // localtime_s sets all fields of `tm` to -1 on error, causing strftime to crash
    }
#else
    localtime_r(&time, &tm);
#endif

    char time_str[20];
    strftime(time_str, sizeof(time_str), "%d.%m.%Y %H:%M:%S", &tm);

    fprintf(stderr, "%s.%06d [%" PRIdMAX "] [%s] %.*s",
            time_str, (int)(duration_cast<microseconds>(now.time_since_epoch()).count() % 1000000),
            (intmax_t)gettid(),
            magic_enum::enum_name(lvl).data(),
            (int)length, message);
}

struct global_info {
    std::atomic<ag::log_level> default_log_level = ag::INFO;
    std::shared_ptr<ag::logger_cb> callback = std::make_shared<ag::logger_cb>(default_callback);

    global_info() {
        spdlog::set_pattern("[%n] %v");
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
