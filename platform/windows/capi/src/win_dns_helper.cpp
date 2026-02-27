#include <csignal>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <fmt/base.h>

#include <nlohmann/json.hpp>

#include "common/cidr_range.h"
#include "common/net_utils.h"
#include "common/wfp_firewall.h"

static constexpr const char *MUTEX_NAME = "AdGuard DNS Helper (8ETpiOi2jbjAdaYvKlYEdQ)";
static constexpr const char *SETTINGS_FILE_NAME = "adguard-win-dns-helper.json";

static_assert(std::atomic_bool::is_always_lock_free, "Atomic bools are not always lock-free");
static std::atomic_bool keep_running{true};

static void signal_handler(int) {
    keep_running = false;
}

static void print_usage() {
    fmt::print(stderr,
            "Usage:\n"
            "\n"
            "    adguard-win-dns-helper\n"
            "    adguard-win-dns-helper <pid> <v4_dns> <v6_dns>\n"
            "\n"
            "<pid> is the process ID of the process that is to be excluded from firewall restrictions"
            " (the DNS proxy process).\n"
            "<v4_dns>/<v6_dns> is a comma-separated list of IPv4/IPv6 DNS server addresses (at most two).\n"
            "Both <v4_dns> and <v6_dns> can be an empty string (\"\").\n"
            "This program must be run with Administrator privileges.\n"
            "When run without arguments, restore the saved DNS settings and exit.\n"
            "When run with arguments, save the current DNS settings, set DNS on the preferred interface,"
            " restrict DNS queries to the specified addresses, and wait for input. Upon receiving any input,"
            " restore the saved DNS settings and exit. Firewall restrictions are only active while the program"
            " is running. Current DNS settings are saved to a file named {} inside the working directory.\n"
            "\n"
            "Exit codes:\n"
            "0 on success, non-zero on error.\n",
            SETTINGS_FILE_NAME);
}

// https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
static bool running_as_administrator() {
    PSID admins_group;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    BOOL result = AllocateAndInitializeSid(
            &nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins_group);
    if (result) {
        if (!CheckTokenMembership(NULL, admins_group, &result)) {
            result = false;
        }
        FreeSid(admins_group);
    }
    return result;
}

class SingleInstanceGuard {
public:
    explicit SingleInstanceGuard(const char *mutex_name) {
        SetLastError(ERROR_SUCCESS);
        m_mutex = CreateMutexA(NULL, FALSE, mutex_name);
        m_already_running = (GetLastError() == ERROR_ALREADY_EXISTS);
    }

    ~SingleInstanceGuard() {
        if (m_mutex) {
            CloseHandle(m_mutex);
        }
    }

    bool already_running() const {
        return m_already_running;
    }

    SingleInstanceGuard(const SingleInstanceGuard &) = delete;
    SingleInstanceGuard &operator=(const SingleInstanceGuard &) = delete;

    SingleInstanceGuard(SingleInstanceGuard &&) = default;
    SingleInstanceGuard &operator=(SingleInstanceGuard &&) = default;

private:
    HANDLE m_mutex = NULL;
    bool m_already_running;
};

struct DnsSettings {
    std::string primary_if_uuid;
    std::optional<std::string> nameserver_v4;
    std::optional<std::string> nameserver_v6;

    static DnsSettings get_current() {
        DnsSettings settings;
        settings.primary_if_uuid = ag::utils::win_get_preferred_adapter_guid();
        settings.nameserver_v4 = ag::utils::win_get_if_nameserver(settings.primary_if_uuid.c_str(), /*v6*/ false);
        settings.nameserver_v6 = ag::utils::win_get_if_nameserver(settings.primary_if_uuid.c_str(), /*v6*/ true);
        return settings;
    }

    static std::optional<DnsSettings> load_from_file(const char *filename) {
        std::ifstream in{filename};
        nlohmann::json json;
        try {
            in >> json;
            DnsSettings settings;
            settings.primary_if_uuid = json["if_uuid"];
            settings.nameserver_v4 = json["v4"].is_null() ? std::nullopt : std::make_optional<std::string>(json["v4"]);
            settings.nameserver_v6 = json["v6"].is_null() ? std::nullopt : std::make_optional<std::string>(json["v6"]);
            return settings;
        } catch (const nlohmann::json::exception &) {
            return std::nullopt;
        }
    }

    bool save_to_file(const char *filename) const {
        nlohmann::json json;
        json["if_uuid"] = primary_if_uuid;
        if (nameserver_v4.has_value()) {
            json["v4"] = *nameserver_v4;
        } else {
            json["v4"] = nullptr;
        }
        if (nameserver_v6.has_value()) {
            json["v6"] = *nameserver_v6;
        } else {
            json["v6"] = nullptr;
        }
        std::ofstream out{filename};
        try {
            out << json;
        } catch (const nlohmann::json::exception &) {
            return false;
        }
        return !out.fail();
    }
};

static std::string win_strerror(DWORD error) {
    char buf[4096]{};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK, nullptr,
            error, 0, buf, sizeof(buf), nullptr);
    return buf;
}

static bool set_dns(const DnsSettings &settings) {
    using P = std::pair<const std::optional<std::string> &, bool>;
    for (auto &[nameserver, v6] : {P{settings.nameserver_v4, false}, P{settings.nameserver_v6, true}}) {
        if (nameserver.has_value()) {
            DWORD error = ag::utils::win_set_if_nameserver(*nameserver, settings.primary_if_uuid.c_str(), v6);
            if (error != ERROR_SUCCESS) {
                fmt::println(stderr, "Failed to set {} NameServer to \"{}\" on interface {}: {}", v6 ? "IPv6" : "IPv4",
                        *nameserver, settings.primary_if_uuid, win_strerror(error));
                return false;
            }
        }
    }
    return true;
}

static bool restore_dns_from_file(const char *filename) {
    if (!std::filesystem::exists(filename)) {
        return true;
    }
    auto settings = DnsSettings::load_from_file(filename);
    std::filesystem::remove(filename);
    if (!settings.has_value()) {
        fmt::println(stderr, "Failed to load settings from file: {}", filename);
        return false;
    }
    return set_dns(*settings);
}

static bool parse_args(int argc, char **argv, uint32_t &out_pid, std::vector<ag::CidrRange> &out_v4,
        std::vector<ag::CidrRange> &out_v6) {
    if (argc != 4) {
        return false;
    }
    if (auto pid = ag::utils::to_integer<uint32_t>(argv[1]); pid.has_value()) {
        out_pid = *pid;
    } else {
        return false;
    }
    using P = std::tuple<std::vector<ag::CidrRange> &, char *, bool>;
    for (auto &[out, arg, v6] : {P{out_v4, argv[2], false}, P{out_v6, argv[3], true}}) {
        auto addrs = ag::utils::split_by(arg, ',');
        if (addrs.size() > 2) {
            return false;
        }
        for (auto &addr : addrs) {
            if (v6 && !ag::utils::is_valid_ip6(addr) || !v6 && !ag::utils::is_valid_ip4(addr)) {
                return false;
            }
            out.emplace_back(addr);
        }
    }
    return true;
}

int main(int argc, char **argv) {
    if (!running_as_administrator()) {
        fmt::println(stderr, "This program has to be run with Administrator privileges");
        return -1;
    }

    SingleInstanceGuard guard{MUTEX_NAME};
    if (guard.already_running()) {
        fmt::println(stderr, "Another instance of this program is already running");
        return -1;
    }

    if (argc == 1) {
        if (!restore_dns_from_file(SETTINGS_FILE_NAME)) {
            fmt::println(stderr, "Failed to restore original settings");
            return -1;
        }
        return 0;
    }

    uint32_t pid;
    std::vector<ag::CidrRange> v4;
    std::vector<ag::CidrRange> v6;

    if (!parse_args(argc, argv, pid, v4, v6)) {
        print_usage();
        return -1;
    }

    if (!restore_dns_from_file(SETTINGS_FILE_NAME)) {
        return -1;
    }

    std::string_view nameserver_v4 = ag::utils::trim(argv[2]);
    std::string_view nameserver_v6 = ag::utils::trim(argv[3]);

    DnsSettings settings = DnsSettings::get_current();
    if (!settings.save_to_file(SETTINGS_FILE_NAME)) {
        fmt::println(stderr, "Failed to save current settings");
        return -1;
    }

    settings.nameserver_v4 = nameserver_v4.empty() ? std::nullopt : std::make_optional<std::string>(nameserver_v4);
    settings.nameserver_v6 = nameserver_v6.empty() ? std::nullopt : std::make_optional<std::string>(nameserver_v6);

    if (!set_dns(settings)) {
        fmt::println(stderr, "Failed to set DNS to (\"{}\", \"{}\")", nameserver_v4, nameserver_v6);
        return -1;
    }

    ag::WfpFirewall fw{L"AdGuard DNS helper", pid};
    auto err = fw.restrict_dns_to(v4, v6);
    if (err) {
        fmt::println(
                stderr, "Failed to restrict DNS to (\"{}\", \"{}\"): {}", nameserver_v4, nameserver_v6, err->str());
        return -1;
    }

    fmt::println(stdout, "Ctrl+C to revert changes and exit\n");

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    while (keep_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (!restore_dns_from_file(SETTINGS_FILE_NAME)) {
        fmt::println(stderr, "Failed to restore original settings");
        return -1;
    }

    return 0;
}
