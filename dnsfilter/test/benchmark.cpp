#include <cstdio>
#include <cstdarg>
#include <string_view>
#include <cstring>
#include <ag_utils.h>
#include <ag_file.h>
#include <ag_logger.h>
#include <ag_sys.h>
#include <dnsfilter.h>

#undef max // `nanoseconds::max()` conflicts with `max` macro from `minwindef.h` on Windows
#include <chrono>

#define DEFAULT_FILTER_PATH "./bench_filter.txt"
#define DEFAULT_DOMAINS_BASE_PATH "./bench_domains.txt"

#define FAIL_WITH_MSG(msg, ...) SPDLOG_ERROR(msg, ##__VA_ARGS__); exit(1)


#define TICK(ts) do { ts = std::chrono::steady_clock::now(); } while (0)


using time_point = std::chrono::time_point<std::chrono::steady_clock>;
using nanoseconds = std::chrono::nanoseconds;

typedef struct {
    struct {
        time_point start_ts;
        time_point end_ts;
        int start_rss;
        int end_rss;
    } load_rules;

    struct {
        size_t tries;
        size_t total_matches;
        size_t effective_blocking_matches;
        size_t effective_exception_matches;
        time_point start_ts;
        time_point end_ts;
        nanoseconds min_per_domain;
        nanoseconds max_per_domain;
        int start_rss;
        int end_rss;
    } match_domains;

    struct {
        time_point start_ts;
        time_point end_ts;
        int start_rss;
        int end_rss;
    } overall;
} test_result_t;


static constexpr std::string_view HELP_MESSAGE =
    "DNS filter benchmarking utility\n"
    "\n"
    "Usage: dnsfilter_benchmark [options...]\n"
    "\n"
    "    -h           print this message\n"
    "    -f <path>    path to filter list file (default='" DEFAULT_FILTER_PATH "')\n"
    "    -d <path>    path to domains list file (default='" DEFAULT_DOMAINS_BASE_PATH "')\n";


static std::vector<std::string> domains;

static bool add_domain(uint32_t idx, std::string_view line, void *arg) {
    if (!line.empty()) {
        size_t pos = line.find(',');
        domains.emplace_back(line.substr((pos != line.npos) ? pos + 1 : 0));
    }
    return true;
}


static int parse_domains_base(std::string_view path) {
    ag::file::handle file = ag::file::open(path, ag::file::RDONLY);
    if (!ag::file::is_valid(file)) {
        SPDLOG_ERROR("failed to read file: {} ({})",
            path, ag::sys::error_string(ag::sys::error_code()));
        return -1;
    }
    ag::file::for_each_line(file, &add_domain, nullptr);
    ag::file::close(file);
    return 0;
}

static int apply_filter_to_base(test_result_t *tr, ag::dnsfilter *filter, ag::dnsfilter::handle handle) {
    time_point before = {};
    time_point after = {};
    nanoseconds elapsed = {};
    nanoseconds min_elapsed = nanoseconds::max();
    nanoseconds max_elapsed = {};

    TICK(tr->match_domains.start_ts);

    size_t domains_num = domains.size();
    size_t report_step = domains_num / 10;

    for (size_t i = 0; i < domains_num; ++i) {
        TICK(before);
        std::vector<ag::dnsfilter::rule> rules = filter->match(handle, domains[i]);
        const ag::dnsfilter::rule *effective_rule = ag::dnsfilter::get_effective_rule(rules);
        TICK(after);

        tr->match_domains.total_matches += rules.size();

        if (effective_rule != nullptr) {
            if (!effective_rule->props.test(ag::dnsfilter::RP_EXCEPTION)) {
                ++tr->match_domains.effective_blocking_matches;
            } else {
                ++tr->match_domains.effective_exception_matches;
            }
        }

        elapsed = std::chrono::duration_cast<nanoseconds>(after - before);
        if (elapsed.count() != 0) {
            if (elapsed < min_elapsed) {
                min_elapsed = elapsed;
            } else if (elapsed > max_elapsed) {
                max_elapsed = elapsed;
            }
        }

        if (i % report_step == 0 && i != 0) {
            SPDLOG_INFO("matched {} domains", i);
        }
    }

    TICK(tr->match_domains.end_ts);

    tr->match_domains.min_per_domain = min_elapsed;
    tr->match_domains.max_per_domain = max_elapsed;

    return 0;
}

static void report_results(const test_result_t *result) {
    SPDLOG_INFO("============================================");
    SPDLOG_INFO("Load rules measurements:");
    std::chrono::duration elapsed = std::chrono::duration<double, std::ratio<1>>(result->load_rules.end_ts - result->load_rules.start_ts);
    SPDLOG_INFO("\tTime elapsed:               {}s", elapsed.count());
    SPDLOG_INFO("\tRSS before:                 {}kB", result->load_rules.start_rss);
    SPDLOG_INFO("\tRSS after:                  {}kB", result->load_rules.end_rss);
    SPDLOG_INFO("\tRSS diff:                   {}kB", result->load_rules.end_rss - result->load_rules.start_rss);
    SPDLOG_INFO("Match domains measurements:");
    SPDLOG_INFO("\tTotal tries:                {}", result->match_domains.tries);
    SPDLOG_INFO("\tTotal rules matched:        {}", result->match_domains.total_matches);
    SPDLOG_INFO("\tEffective blocking rules:   {}", result->match_domains.effective_blocking_matches);
    SPDLOG_INFO("\tEffective exception rules:  {}", result->match_domains.effective_exception_matches);
    elapsed = std::chrono::duration<double, std::ratio<1>>(result->match_domains.end_ts - result->match_domains.start_ts);
    SPDLOG_INFO("\tTime elapsed:               {}s", elapsed.count());
    SPDLOG_INFO("\tMin per-domain:             {}ns", result->match_domains.min_per_domain.count());
    SPDLOG_INFO("\tMax per-domain:             {}ns", result->match_domains.max_per_domain.count());
    SPDLOG_INFO("\tAverage per-domain:         {}ns", uint64_t(elapsed.count() * std::nano::den / result->match_domains.tries));
    SPDLOG_INFO("\tRSS before:                 {}kB", result->match_domains.start_rss);
    SPDLOG_INFO("\tRSS after:                  {}kB", result->match_domains.end_rss);
    SPDLOG_INFO("\tRSS diff:                   {}kB", result->match_domains.end_rss - result->match_domains.start_rss);
    SPDLOG_INFO("Overall measurements:");
    elapsed = std::chrono::duration<double, std::ratio<1>>(result->overall.end_ts - result->overall.start_ts);
    SPDLOG_INFO("\tTime elapsed:               {}s", elapsed.count());
    SPDLOG_INFO("\tRSS before:                 {}kB", result->overall.start_rss);
    SPDLOG_INFO("\tRSS after:                  {}kB", result->overall.end_rss);
    SPDLOG_INFO("\tRSS diff:                   {}kB", result->overall.end_rss - result->overall.start_rss);
    SPDLOG_INFO("============================================");
}


int main(int argc, char **argv) {
    std::string_view filter_list_path = DEFAULT_FILTER_PATH;
    std::string_view domains_base_path = DEFAULT_DOMAINS_BASE_PATH;

    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp(argv[i], "-h")) {
            SPDLOG_INFO("{}", HELP_MESSAGE);
            return 0;
        } else if (0 == strcmp(argv[i], "-f")) {
            if (i + 1 == argc) {
                FAIL_WITH_MSG("option 'f' needs a value\n{}", HELP_MESSAGE);
            }
            filter_list_path = argv[i+1];
            ++i;
        } else if (0 == strcmp(argv[i], "-d")) {
            if (i + 1 == argc) {
                FAIL_WITH_MSG("option 'd' needs a value\n{}", HELP_MESSAGE);
            }
            domains_base_path = argv[i+1];
            ++i;
        } else {
            FAIL_WITH_MSG("unknown option %s\n{}", argv[i], HELP_MESSAGE);
        }
    }

    test_result_t result = {};

    SPDLOG_INFO("Parsing domains base...");
    if (0 != parse_domains_base(domains_base_path)) {
        FAIL_WITH_MSG("failed to parse domains base");
    }
    SPDLOG_INFO("...domains base parsed");

    result.match_domains.tries = domains.size();

    result.overall.start_rss = ag::sys::current_rss();
    TICK(result.overall.start_ts);

    result.load_rules.start_rss = ag::sys::current_rss();

    SPDLOG_INFO("Loading rules in filter...");
    ag::dnsfilter filter;
    ag::dnsfilter::engine_params filter_params = { { { 0, std::string(filter_list_path) } } };

    TICK(result.load_rules.start_ts);
    std::optional<ag::dnsfilter::handle> handle = filter.create(filter_params);
    TICK(result.load_rules.end_ts);
    result.load_rules.end_rss = ag::sys::current_rss();
    if (!handle.has_value()) {
        SPDLOG_INFO("...failed to load rules");
        exit(-1);
    }
    SPDLOG_INFO("...rules loaded");

    SPDLOG_INFO("Matching domains against rules...");
    result.match_domains.start_rss = ag::sys::current_rss();
    apply_filter_to_base(&result, &filter, handle.value());
    result.match_domains.end_rss = ag::sys::current_rss();
    SPDLOG_INFO("...domains matched");

    filter.destroy(handle.value());

    TICK(result.overall.end_ts);
    result.overall.end_rss = ag::sys::current_rss();

    report_results(&result);
}
