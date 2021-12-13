#include <cstdio>
#include <cstdarg>
#include <string_view>
#include <cstring>
#include "common/utils.h"
#include <ag_file.h>
#include "common/logger.h"
#include <ag_sys.h>
#include <dnsfilter.h>

#undef max // `nanoseconds::max()` conflicts with `max` macro from `minwindef.h` on Windows
#include <chrono>

#define DEFAULT_FILTER_PATH "./bench_filter.txt"
#define DEFAULT_DOMAINS_BASE_PATH "./bench_domains.txt"

static ag::Logger logger{"dnsfilter_benchmark"};

#define FAIL_WITH_MSG(msg, ...) errlog(logger, msg, ##__VA_ARGS__); exit(1)

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
    ag::file::handle file = ag::file::open(std::string(path), ag::file::RDONLY);
    if (!ag::file::is_valid(file)) {
        errlog(logger, "failed to read file: {} ({})",
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
        std::vector<ag::dnsfilter::rule> rules = filter->match(handle, { domains[i], LDNS_RR_TYPE_A });
        ag::dnsfilter::effective_rules effective_rules = ag::dnsfilter::get_effective_rules(rules);
        TICK(after);

        tr->match_domains.total_matches += rules.size();

        if (!effective_rules.leftovers.empty()) {
            if (const auto *adblock_info = std::get_if<ag::dnsfilter::adblock_rule_info>(&effective_rules.leftovers[0]->content);
                    adblock_info != nullptr && !adblock_info->props.test(ag::dnsfilter::DARP_EXCEPTION)) {
                tr->match_domains.effective_blocking_matches += effective_rules.leftovers.size();
            } else {
                tr->match_domains.effective_exception_matches += effective_rules.leftovers.size();
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
            infolog(logger, "matched {} domains", i);
        }
    }

    TICK(tr->match_domains.end_ts);

    tr->match_domains.min_per_domain = min_elapsed;
    tr->match_domains.max_per_domain = max_elapsed;

    return 0;
}

static void report_results(const test_result_t *result) {
    infolog(logger, "============================================");
    infolog(logger, "Load rules measurements:");
    std::chrono::duration elapsed = std::chrono::duration<double, std::ratio<1>>(result->load_rules.end_ts - result->load_rules.start_ts);
    infolog(logger, "\tTime elapsed:               {}s", elapsed.count());
    infolog(logger, "\tRSS before:                 {}kB", result->load_rules.start_rss);
    infolog(logger, "\tRSS after:                  {}kB", result->load_rules.end_rss);
    infolog(logger, "\tRSS diff:                   {}kB", result->load_rules.end_rss - result->load_rules.start_rss);
    infolog(logger, "Match domains measurements:");
    infolog(logger, "\tTotal tries:                {}", result->match_domains.tries);
    infolog(logger, "\tTotal rules matched:        {}", result->match_domains.total_matches);
    infolog(logger, "\tEffective blocking rules:   {}", result->match_domains.effective_blocking_matches);
    infolog(logger, "\tEffective exception rules:  {}", result->match_domains.effective_exception_matches);
    elapsed = std::chrono::duration<double, std::ratio<1>>(result->match_domains.end_ts - result->match_domains.start_ts);
    infolog(logger, "\tTime elapsed:               {}s", elapsed.count());
    infolog(logger, "\tMin per-domain:             {}ns", result->match_domains.min_per_domain.count());
    infolog(logger, "\tMax per-domain:             {}ns", result->match_domains.max_per_domain.count());
    infolog(logger, "\tAverage per-domain:         {}ns", uint64_t(elapsed.count() * std::nano::den / result->match_domains.tries));
    infolog(logger, "\tRSS before:                 {}kB", result->match_domains.start_rss);
    infolog(logger, "\tRSS after:                  {}kB", result->match_domains.end_rss);
    infolog(logger, "\tRSS diff:                   {}kB", result->match_domains.end_rss - result->match_domains.start_rss);
    infolog(logger, "Overall measurements:");
    elapsed = std::chrono::duration<double, std::ratio<1>>(result->overall.end_ts - result->overall.start_ts);
    infolog(logger, "\tTime elapsed:               {}s", elapsed.count());
    infolog(logger, "\tRSS before:                 {}kB", result->overall.start_rss);
    infolog(logger, "\tRSS after:                  {}kB", result->overall.end_rss);
    infolog(logger, "\tRSS diff:                   {}kB", result->overall.end_rss - result->overall.start_rss);
    infolog(logger, "============================================");
}


int main(int argc, char **argv) {
    std::string_view filter_list_path = DEFAULT_FILTER_PATH;
    std::string_view domains_base_path = DEFAULT_DOMAINS_BASE_PATH;

    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp(argv[i], "-h")) {
            infolog(logger, "{}", HELP_MESSAGE);
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

    infolog(logger, "Parsing domains base...");
    if (0 != parse_domains_base(domains_base_path)) {
        FAIL_WITH_MSG("failed to parse domains base");
    }
    infolog(logger, "...domains base parsed");

    result.match_domains.tries = domains.size();

    result.overall.start_rss = ag::sys::current_rss();
    TICK(result.overall.start_ts);

    result.load_rules.start_rss = ag::sys::current_rss();

    infolog(logger, "Loading rules in filter...");
    ag::dnsfilter filter;
    ag::dnsfilter::engine_params filter_params = { { { 0, std::string(filter_list_path) } } };

    TICK(result.load_rules.start_ts);
    auto [handle, err_or_warn] = filter.create(filter_params);
    if (!handle) {
        errlog(logger, "...failed to load rules: {}", *err_or_warn);
        exit(-1);
    }
    TICK(result.load_rules.end_ts);
    result.load_rules.end_rss = ag::sys::current_rss();
    if (err_or_warn) {
        warnlog(logger, "... rules loaded with warnings: {}", *err_or_warn);
    } else {
        infolog(logger, "...rules loaded");
    }

    infolog(logger, "Matching domains against rules...");
    result.match_domains.start_rss = ag::sys::current_rss();
    apply_filter_to_base(&result, &filter, handle);
    result.match_domains.end_rss = ag::sys::current_rss();
    infolog(logger, "...domains matched");

    filter.destroy(handle);

    TICK(result.overall.end_ts);
    result.overall.end_rss = ag::sys::current_rss();

    report_results(&result);
}
