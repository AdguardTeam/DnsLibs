// Windows `system://` upstream (DnsQueryEx(), Windows 8+) tests. The record and reply conversions are tested
// with hand-made `DNS_RECORDW`s. The always-on exchange tests only query names which the DNS Client
// service answers by itself (e.g. `localhost`), or which are never answered in time, so they stay offline.
// Shared infrastructure comes from upstream_test_fixture.h.

#include <algorithm>
#include <array>
#include <cstring>

#include <magic_enum/magic_enum.hpp>

// The fixture includes `winsock2.h` with the required Windows macros, so it must come before `iphlpapi.h`.
#include "upstream_test_fixture.h"

#include <iphlpapi.h>

#include "../upstream_system_windows.h"

namespace ag::dns::upstream::test {

static constexpr uint16_t REQUEST_ID = 0x1234;
static constexpr DWORD TEST_TTL = 300;

// The index of the interface that would be used to reach `ip` (in network byte order).
static std::optional<DWORD> best_interface_index(IPAddr ip) {
    DWORD index = 0;
    if (NO_ERROR != GetBestInterface(ip, &index)) {
        return std::nullopt;
    }
    return index;
}

static ldns_pkt_ptr create_query(const char *name, ldns_rr_type type, ldns_rr_class cls = LDNS_RR_CLASS_IN) {
    ldns_pkt *pkt = ldns_pkt_query_new(ldns_dname_new_frm_str(name), type, cls, LDNS_RD);
    ldns_pkt_set_id(pkt, REQUEST_ID);
    return ldns_pkt_ptr{pkt};
}

static std::string rr_to_string(const ldns_rr *rr) {
    AllocatedPtr<char> str{ldns_rr2str(rr)};
    std::string_view view = (str != nullptr) ? str.get() : "";
    while (view.ends_with('\n')) {
        view.remove_suffix(1);
    }
    return std::string{view};
}

// The record data of the records of a type, sorted: comparable between servers, unlike TTLs.
static std::vector<std::string> rdata_of_type(const ldns_rr_list *list, ldns_rr_type type) {
    std::vector<std::string> result;
    for (size_t i = 0; i < ldns_rr_list_rr_count(list); ++i) {
        const ldns_rr *rr = ldns_rr_list_rr(list, i);
        if (ldns_rr_get_type(rr) != type) {
            continue;
        }
        std::string rdata;
        for (size_t j = 0; j < ldns_rr_rd_count(rr); ++j) {
            AllocatedPtr<char> rdf{ldns_rdf2str(ldns_rr_rdf(rr, j))};
            rdata += AG_FMT("{}{}", j == 0 ? "" : " ", (rdf != nullptr) ? rdf.get() : "<null>");
        }
        result.emplace_back(std::move(rdata));
    }
    std::sort(result.begin(), result.end());
    return result;
}

// Checks that the reply contains `expected_addr` in an answer record of `type`.
static TestError check_local_reply(const ldns_pkt &reply, ldns_rr_type type, std::string_view expected_addr) {
    if (ldns_pkt_get_rcode(&reply) != LDNS_RCODE_NOERROR) {
        return AG_FMT("Unexpected rcode: {}", (int) ldns_pkt_get_rcode(&reply));
    }
    if (ldns_pkt_id(&reply) != REQUEST_ID) {
        return AG_FMT("Reply ID {} doesn't match the request ID", ldns_pkt_id(&reply));
    }
    if (!ldns_pkt_qr(&reply)) {
        return "The reply doesn't have the QR bit set";
    }
    std::vector<std::string> addrs = rdata_of_type(ldns_pkt_answer(&reply), type);
    if (std::find(addrs.begin(), addrs.end(), expected_addr) == addrs.end()) {
        return AG_FMT("No {} in the answer section", expected_addr);
    }
    return std::nullopt;
}

static coro::Task<TestError> resolve_localhost(
        Upstream &upstream, utils::TransportProtocol proto, ldns_rr_type type = LDNS_RR_TYPE_A) {
    DnsMessageInfo info{.proto = proto};
    ldns_pkt_ptr request = create_query("localhost.", type);
    auto reply = co_await upstream.exchange(request.get(), &info);
    if (reply.has_error()) {
        co_return AG_FMT("proto={}: {}", magic_enum::enum_name(proto), reply.error()->str());
    }
    TestError error = check_local_reply(*reply.value(), type, (type == LDNS_RR_TYPE_A) ? "127.0.0.1" : "::1");
    if (error) {
        co_return AG_FMT("proto={}: {}", magic_enum::enum_name(proto), *error);
    }
    co_return std::nullopt;
}

// A name nobody has, so that the query takes a while
static std::string unique_name(size_t i) {
    return AG_FMT("ag-dnslibs-test-{}-{}.invalid.", i, GetTickCount64());
}

static coro::Task<Upstream::ExchangeResult> exchange_name(Upstream *upstream, std::string name, ldns_rr_type type) {
    ldns_pkt_ptr request = create_query(name.c_str(), type);
    co_return co_await upstream->exchange(request.get());
}

// The observations of `exchange_and_retry()`.
struct RetryState {
    bool destroying = false;      ///< Set by the test before the upstream is destroyed.
    bool first_completed = false; ///< Whether the first query completed before the destruction started.
    bool retried_during_destruction = false;
    std::optional<Upstream::ExchangeResult> retry_result;
};

// Issues a query and, once it completes, immediately issues another one. If the first query is
// completed by the upstream destructor, the retry is sent while the upstream is being destroyed.
static coro::Task<void> exchange_and_retry(Upstream *upstream, RetryState &state) {
    ldns_pkt_ptr first_request = create_query(unique_name(0).c_str(), LDNS_RR_TYPE_A);
    (void) co_await upstream->exchange(first_request.get());
    state.first_completed = true;
    state.retried_during_destruction = state.destroying;
    ldns_pkt_ptr second_request = create_query(unique_name(1).c_str(), LDNS_RR_TYPE_A);
    state.retry_result = co_await upstream->exchange(second_request.get());
}

/**
 * A `DNS_RECORDW` with room for the variable-length data past the end of `DNS_RECORDW::Data`
 * (e.g. `DNS_TXT_DATAW::pStringArray`, `DNS_KEY_DATA::Key`), as `DnsQueryEx()` lays them out.
 */
struct TestRecord {
    DNS_RECORDW record{};
    std::array<uint8_t, 256> extra{};
};

static std::unique_ptr<TestRecord> make_record(PCWSTR name, WORD type, DWORD section = DnsSectionAnswer) {
    auto result = std::make_unique<TestRecord>();
    result->record.pName = const_cast<PWSTR>(name); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    result->record.wType = type;
    result->record.dwTtl = TEST_TTL;
    result->record.Flags.S.Section = section;
    return result;
}

static std::unique_ptr<TestRecord> make_a_record(PCWSTR name, const char *addr, DWORD section = DnsSectionAnswer) {
    auto result = make_record(name, DNS_TYPE_A, section);
    inet_pton(AF_INET, addr, &result->record.Data.A.IpAddress);
    result->record.wDataLength = sizeof(DNS_A_DATA);
    return result;
}

TEST(SystemUpstreamRecordTest, ConvertsA) {
    auto rec = make_a_record(L"example.com", "1.2.3.4");
    ldns_rr_ptr rr = system_record_to_ldns(rec->record);
    ASSERT_NE(nullptr, rr);
    ASSERT_EQ("example.com.\t300\tIN\tA\t1.2.3.4", rr_to_string(rr.get()));
}

TEST(SystemUpstreamRecordTest, ConvertsAaaa) {
    auto rec = make_record(L"example.com.", DNS_TYPE_AAAA);
    inet_pton(AF_INET6, "2001:db8::1", &rec->record.Data.AAAA.Ip6Address);
    ldns_rr_ptr rr = system_record_to_ldns(rec->record);
    ASSERT_NE(nullptr, rr);
    ASSERT_EQ("example.com.\t300\tIN\tAAAA\t2001:db8::1", rr_to_string(rr.get()));
}

TEST(SystemUpstreamRecordTest, ConvertsCname) {
    auto rec = make_record(L"www.example.com", DNS_TYPE_CNAME);
    rec->record.Data.CNAME.pNameHost =
            const_cast<PWSTR>(L"example.com"); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    ldns_rr_ptr rr = system_record_to_ldns(rec->record);
    ASSERT_NE(nullptr, rr);
    ASSERT_EQ("www.example.com.\t300\tIN\tCNAME\texample.com.", rr_to_string(rr.get()));
}

TEST(SystemUpstreamRecordTest, ConvertsMx) {
    auto rec = make_record(L"example.com", DNS_TYPE_MX);
    rec->record.Data.MX.pNameExchange =
            const_cast<PWSTR>(L"mail.example.com"); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    rec->record.Data.MX.wPreference = 258;          // Distinguishes the byte orders
    ldns_rr_ptr rr = system_record_to_ldns(rec->record);
    ASSERT_NE(nullptr, rr);
    ASSERT_EQ("example.com.\t300\tIN\tMX\t258 mail.example.com.", rr_to_string(rr.get()));
}

TEST(SystemUpstreamRecordTest, ConvertsTxt) {
    auto rec = make_record(L"example.com", DNS_TYPE_TEXT);
    rec->record.Data.TXT.dwStringCount = 2;
    PWSTR *strings = rec->record.Data.TXT.pStringArray;
    strings[0] = const_cast<PWSTR>(L"hello"); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    strings[1] = const_cast<PWSTR>(L"world"); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    ldns_rr_ptr rr = system_record_to_ldns(rec->record);
    ASSERT_NE(nullptr, rr);
    ASSERT_EQ("example.com.\t300\tIN\tTXT\t\"hello\" \"world\"", rr_to_string(rr.get()));
}

TEST(SystemUpstreamRecordTest, ConvertsSoa) {
    auto rec = make_record(L"example.com", DNS_TYPE_SOA);
    auto &soa = rec->record.Data.SOA;
    soa.pNamePrimaryServer = const_cast<PWSTR>(L"ns.example.com");    // NOLINT(cppcoreguidelines-pro-type-const-cast)
    soa.pNameAdministrator = const_cast<PWSTR>(L"admin.example.com"); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    soa.dwSerialNo = 2024010101;
    soa.dwRefresh = 7200;
    soa.dwRetry = 3600;
    soa.dwExpire = 1209600;
    soa.dwDefaultTtl = 300;
    ldns_rr_ptr rr = system_record_to_ldns(rec->record);
    ASSERT_NE(nullptr, rr);
    ASSERT_EQ("example.com.\t300\tIN\tSOA\tns.example.com. admin.example.com. 2024010101 7200 3600 1209600 300",
            rr_to_string(rr.get()));
}

TEST(SystemUpstreamRecordTest, ConvertsSrv) {
    auto rec = make_record(L"_sip._tcp.example.com", DNS_TYPE_SRV);
    rec->record.Data.SRV.pNameTarget =
            const_cast<PWSTR>(L"sip.example.com"); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    rec->record.Data.SRV.wPriority = 10;
    rec->record.Data.SRV.wWeight = 20;
    rec->record.Data.SRV.wPort = 5060;
    ldns_rr_ptr rr = system_record_to_ldns(rec->record);
    ASSERT_NE(nullptr, rr);
    ASSERT_EQ("_sip._tcp.example.com.\t300\tIN\tSRV\t10 20 5060 sip.example.com.", rr_to_string(rr.get()));
}

// The structure fields are in the host byte order, and the key is copied as is
TEST(SystemUpstreamRecordTest, ConvertsDnskey) {
    static constexpr uint8_t KEY[] = {0x03, 0x01, 0x00, 0x01, 0xab, 0xcd};
    auto rec = make_record(L"example.com", DNS_TYPE_DNSKEY);
    auto &key = rec->record.Data.DNSKEY;
    key.wFlags = 257;
    key.chProtocol = 3;
    key.chAlgorithm = LDNS_RSASHA256;
    key.wKeyLength = sizeof(KEY);
    std::memcpy(key.Key, KEY, sizeof(KEY));
    ldns_rr_ptr rr = system_record_to_ldns(rec->record);
    ASSERT_NE(nullptr, rr);
    ASSERT_EQ(LDNS_RR_TYPE_DNSKEY, ldns_rr_get_type(rr.get()));
    ASSERT_EQ(4, ldns_rr_rd_count(rr.get()));
    ASSERT_EQ(257, ldns_rdf2native_int16(ldns_rr_rdf(rr.get(), 0)));
    ASSERT_EQ(3, ldns_rdf2native_int8(ldns_rr_rdf(rr.get(), 1)));
    ASSERT_EQ(LDNS_RSASHA256, ldns_rdf2native_int8(ldns_rr_rdf(rr.get(), 2)));
    const ldns_rdf *key_rdf = ldns_rr_rdf(rr.get(), 3);
    ASSERT_EQ(sizeof(KEY), ldns_rdf_size(key_rdf));
    ASSERT_EQ(0, std::memcmp(KEY, ldns_rdf_data(key_rdf), sizeof(KEY)));
}

// `DnsQueryEx()` fills in `DNS_SVCB_DATA` only for `DNS_QUERY_PARSE_ALL_RECORDS` queries, which
// require `DNS_QUERY_REQUEST3` (not available on Windows 8); otherwise SVCB and HTTPS are returned
// as the raw RDATA, which is marshalled as is.
TEST(SystemUpstreamRecordTest, ConvertsSvcbAndHttps) {
    // priority 1, target ".", alpn "h2", "h3"
    static constexpr uint8_t RDATA[] = {0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x06, 0x02, 'h', '2', 0x02, 'h', '3'};
    for (WORD type : {(WORD) LDNS_RR_TYPE_SVCB, (WORD) LDNS_RR_TYPE_HTTPS}) {
        auto rec = make_record(L"example.com", type);
        std::memcpy(&rec->record.Data, RDATA, sizeof(RDATA));
        rec->record.wDataLength = sizeof(RDATA);
        ldns_rr_ptr rr = system_record_to_ldns(rec->record);
        ASSERT_NE(nullptr, rr) << type;
        ASSERT_EQ(type, ldns_rr_get_type(rr.get()));
        ASSERT_EQ(AG_FMT("example.com.\t300\tIN\t{}\t1 . alpn=h2,h3", type == LDNS_RR_TYPE_SVCB ? "SVCB" : "HTTPS"),
                rr_to_string(rr.get()))
                << type;
    }
}

// Malformed RDATA of a supported type is rejected by the ldns parser
TEST(SystemUpstreamRecordTest, RejectsMalformedSvcb) {
    static constexpr uint8_t TRUNCATED_PRIORITY[] = {0x00};
    auto rec = make_record(L"example.com", LDNS_RR_TYPE_SVCB);
    std::memcpy(&rec->record.Data, TRUNCATED_PRIORITY, sizeof(TRUNCATED_PRIORITY));
    rec->record.wDataLength = sizeof(TRUNCATED_PRIORITY);
    ASSERT_EQ(nullptr, system_record_to_ldns(rec->record));
}

TEST(SystemUpstreamRecordTest, RejectsInvalidNames) {
    std::wstring long_label(64, L'a');
    for (const std::wstring &name : {long_label + L".com", std::wstring{L"a..com"}, std::wstring{L".com"}}) {
        auto rec = make_a_record(name.c_str(), "1.2.3.4");
        ASSERT_EQ(nullptr, system_record_to_ldns(rec->record)) << utils::from_wstring(name);
    }

    auto rec = make_a_record(nullptr, "1.2.3.4");
    ASSERT_EQ(nullptr, system_record_to_ldns(rec->record));

    auto cname = make_record(L"example.com", DNS_TYPE_CNAME);
    std::wstring too_long;
    for (int i = 0; i < 5; ++i) {
        too_long += std::wstring(60, L'a') + L".";
    }
    cname->record.Data.CNAME.pNameHost = too_long.data();
    ASSERT_EQ(nullptr, system_record_to_ldns(cname->record));
}

TEST(SystemUpstreamRecordTest, RejectsUnsupportedType) {
    for (WORD type : {(WORD) DNS_TYPE_WKS, (WORD) LDNS_RR_TYPE_CAA}) {
        auto rec = make_record(L"example.com", type);
        ASSERT_EQ(nullptr, system_record_to_ldns(rec->record)) << type;
    }
}

TEST(SystemUpstreamReplyTest, MapsSections) {
    ldns_pkt_ptr request = create_query("example.com.", LDNS_RR_TYPE_A);
    auto local = make_a_record(L"example.com", "1.2.3.4", DnsSectionQuestion);
    auto answer = make_a_record(L"example.com", "5.6.7.8", DnsSectionAnswer);
    auto authority = make_record(L"example.com", DNS_TYPE_NS, DnsSectionAuthority);
    authority->record.Data.NS.pNameHost =
            const_cast<PWSTR>(L"ns.example.com"); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    auto additional = make_a_record(L"ns.example.com", "9.9.9.9", DnsSectionAddtional);
    auto opt = make_record(L"", DNS_TYPE_OPT, DnsSectionAddtional);
    auto unsupported = make_record(L"example.com", DNS_TYPE_WKS, DnsSectionAnswer);
    auto unsupported_raw = make_record(L"example.com", LDNS_RR_TYPE_CAA, DnsSectionAnswer);
    local->record.pNext = &answer->record;
    answer->record.pNext = &authority->record;
    authority->record.pNext = &additional->record;
    additional->record.pNext = &opt->record;
    opt->record.pNext = &unsupported->record;
    unsupported->record.pNext = &unsupported_raw->record;

    auto result = make_system_reply(request.get(), ERROR_SUCCESS, &local->record);
    ASSERT_FALSE(result.has_error()) << result.error()->str();
    const ldns_pkt *reply = result.value().get();
    ASSERT_EQ(REQUEST_ID, ldns_pkt_id(reply));
    ASSERT_TRUE(ldns_pkt_qr(reply));
    ASSERT_TRUE(ldns_pkt_rd(reply));
    ASSERT_TRUE(ldns_pkt_ra(reply));
    ASSERT_FALSE(ldns_pkt_aa(reply));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(reply));
    ASSERT_EQ(1, ldns_pkt_qdcount(reply));
    ASSERT_EQ((std::vector<std::string>{"1.2.3.4", "5.6.7.8"}), rdata_of_type(ldns_pkt_answer(reply), LDNS_RR_TYPE_A));
    ASSERT_EQ(2, ldns_pkt_ancount(reply));
    ASSERT_EQ(std::vector<std::string>{"ns.example.com."}, rdata_of_type(ldns_pkt_authority(reply), LDNS_RR_TYPE_NS));
    ASSERT_EQ(1, ldns_pkt_nscount(reply));
    ASSERT_EQ(std::vector<std::string>{"9.9.9.9"}, rdata_of_type(ldns_pkt_additional(reply), LDNS_RR_TYPE_A));
    ASSERT_EQ(1, ldns_pkt_arcount(reply));
}

// The system resolver doesn't return the SOA record for negative answers, so a fake one is added
TEST(SystemUpstreamReplyTest, AddsSoaToNegativeReplies) {
    ldns_pkt_ptr request = create_query("example.com.", LDNS_RR_TYPE_A);
    for (auto [status, rcode] : {std::pair{(DNS_STATUS) DNS_ERROR_RCODE_NAME_ERROR, LDNS_RCODE_NXDOMAIN},
                 std::pair{(DNS_STATUS) DNS_INFO_NO_RECORDS, LDNS_RCODE_NOERROR}}) {
        auto result = make_system_reply(request.get(), status, nullptr);
        ASSERT_FALSE(result.has_error()) << result.error()->str();
        const ldns_pkt *reply = result.value().get();
        ASSERT_EQ(rcode, ldns_pkt_get_rcode(reply));
        ASSERT_EQ(0, ldns_pkt_ancount(reply));
        ASSERT_EQ(1, ldns_pkt_nscount(reply));
        const ldns_rr *soa = ldns_rr_list_rr(ldns_pkt_authority(reply), 0);
        ASSERT_EQ(LDNS_RR_TYPE_SOA, ldns_rr_get_type(soa));
        ASSERT_EQ(
                0, ldns_dname_compare(ldns_rr_owner(soa), ldns_rr_owner(ldns_rr_list_rr(ldns_pkt_question(reply), 0))));
    }
}

TEST(SystemUpstreamReplyTest, KeepsReturnedSoa) {
    ldns_pkt_ptr request = create_query("nx.example.com.", LDNS_RR_TYPE_A);
    auto rec = make_record(L"example.com", DNS_TYPE_SOA, DnsSectionAuthority);
    auto &soa = rec->record.Data.SOA;
    soa.pNamePrimaryServer = const_cast<PWSTR>(L"ns.example.com");    // NOLINT(cppcoreguidelines-pro-type-const-cast)
    soa.pNameAdministrator = const_cast<PWSTR>(L"admin.example.com"); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    auto result = make_system_reply(request.get(), DNS_ERROR_RCODE_NAME_ERROR, &rec->record);
    ASSERT_FALSE(result.has_error()) << result.error()->str();
    ASSERT_EQ(1, ldns_pkt_nscount(result.value().get()));
    ASSERT_EQ(std::vector<std::string>{"ns.example.com. admin.example.com. 0 0 0 0 0"},
            rdata_of_type(ldns_pkt_authority(result.value().get()), LDNS_RR_TYPE_SOA));
}

TEST(SystemUpstreamReplyTest, MapsRcodes) {
    ldns_pkt_ptr request = create_query("example.com.", LDNS_RR_TYPE_A);
    for (auto [status, rcode] : {
                 std::pair{(DNS_STATUS) DNS_ERROR_RCODE_FORMAT_ERROR, LDNS_RCODE_FORMERR},
                 std::pair{(DNS_STATUS) DNS_ERROR_RCODE_SERVER_FAILURE, LDNS_RCODE_SERVFAIL},
                 std::pair{(DNS_STATUS) DNS_ERROR_RCODE_NOT_IMPLEMENTED, LDNS_RCODE_NOTIMPL},
                 std::pair{(DNS_STATUS) DNS_ERROR_RCODE_REFUSED, LDNS_RCODE_REFUSED},
         }) {
        auto result = make_system_reply(request.get(), status, nullptr);
        ASSERT_FALSE(result.has_error()) << result.error()->str();
        ASSERT_EQ(rcode, ldns_pkt_get_rcode(result.value().get())) << status;
        ASSERT_EQ(0, ldns_pkt_nscount(result.value().get())) << status;
    }
}

TEST(SystemUpstreamReplyTest, MapsErrors) {
    ldns_pkt_ptr request = create_query("example.com.", LDNS_RR_TYPE_A);
    for (DNS_STATUS status : {(DNS_STATUS) ERROR_TIMEOUT, (DNS_STATUS) WSAETIMEDOUT}) {
        auto result = make_system_reply(request.get(), status, nullptr);
        ASSERT_TRUE(result.has_error()) << status;
        ASSERT_EQ(DnsError::AE_TIMED_OUT, result.error()->value()) << status;
    }
    auto result = make_system_reply(request.get(), ERROR_INVALID_PARAMETER, nullptr);
    ASSERT_TRUE(result.has_error());
    ASSERT_EQ(DnsError::AE_INTERNAL_ERROR, result.error()->value());
}

// The EDNS options of the request aren't echoed, while the rest of EDNS is
TEST(SystemUpstreamReplyTest, DropsEdnsOptions) {
    static constexpr uint16_t UDP_SIZE = 1232;
    static constexpr uint8_t OPTION[] = {0x00, 0x0a, 0x00, 0x02, 0xab, 0xcd}; // COOKIE, truncated
    ldns_pkt_ptr request = create_query("example.com.", LDNS_RR_TYPE_A);
    ldns_pkt_set_edns_udp_size(request.get(), UDP_SIZE);
    ldns_pkt_set_edns_do(request.get(), true);
    ldns_pkt_set_edns_data(request.get(), ldns_rdf_new_frm_data(LDNS_RDF_TYPE_UNKNOWN, sizeof(OPTION), OPTION));
    auto result = make_system_reply(request.get(), ERROR_SUCCESS, nullptr);
    ASSERT_FALSE(result.has_error()) << result.error()->str();
    const ldns_pkt *reply = result.value().get();
    ASSERT_EQ(nullptr, ldns_pkt_edns_data(reply));
    ASSERT_EQ(UDP_SIZE, ldns_pkt_edns_udp_size(reply));
    ASSERT_TRUE(ldns_pkt_edns_do(reply));
}

TEST(SystemUpstreamQueryTest, Name) {
    struct Case {
        const char *name;
        std::optional<std::wstring> expected;
    };
    for (const Case &c : {
                 Case{"example.com.", L"example.com"},
                 Case{"Example.COM", L"Example.COM"},
                 Case{".", L"."},
                 Case{"caf\xc3\xa9.com.", L"caf\u00e9.com"},
                 Case{"a\\.b.com.", std::nullopt},
                 Case{"a\\000b.com.", std::nullopt},
                 Case{"\\255.com.", std::nullopt},
         }) {
        ldns_pkt_ptr request = create_query(c.name, LDNS_RR_TYPE_A);
        ASSERT_NE(nullptr, request) << c.name;
        ASSERT_EQ(c.expected, system_query_name(request.get())) << c.name;
    }

    ldns_pkt_ptr no_question{ldns_pkt_new()};
    ASSERT_EQ(std::nullopt, system_query_name(no_question.get()));
}

TEST(SystemUpstreamQueryTest, Options) {
    ldns_pkt_ptr request = create_query("example.com.", LDNS_RR_TYPE_A);
    ULONG64 udp = system_query_options(request.get(), false);
    ASSERT_TRUE(udp & DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE);
    ASSERT_FALSE(udp & DNS_QUERY_USE_TCP_ONLY);
    ASSERT_TRUE(udp & DNS_QUERY_TREAT_AS_FQDN);
    ASSERT_FALSE(udp & DNS_QUERY_DNSSEC_OK);
    ASSERT_FALSE(udp & DNS_QUERY_DNSSEC_CHECKING_DISABLED);

    ULONG64 tcp = system_query_options(request.get(), true);
    ASSERT_TRUE(tcp & DNS_QUERY_USE_TCP_ONLY);
    ASSERT_FALSE(tcp & DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE);

    ldns_pkt_set_edns_do(request.get(), true);
    ldns_pkt_set_cd(request.get(), true);
    ULONG64 dnssec = system_query_options(request.get(), false);
    ASSERT_TRUE(dnssec & DNS_QUERY_DNSSEC_OK);
    ASSERT_TRUE(dnssec & DNS_QUERY_DNSSEC_CHECKING_DISABLED);
}

TEST_F(UpstreamTest, SystemUpstreamInitAllInterfaces) {
    co_await m_loop->co_submit();
    auto upstream_res = create_upstream({"system://"});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
}

TEST_F(UpstreamTest, SystemUpstreamInitInterfaceIndex) {
    co_await m_loop->co_submit();
    std::optional<DWORD> index = best_interface_index(htonl(INADDR_LOOPBACK));
    ASSERT_TRUE(index.has_value());
    auto upstream_res = create_upstream({AG_FMT("system://{}", *index)});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
}

// `localhost` is answered by the DNS Client service itself, both over UDP and TCP.
TEST_F(UpstreamTest, SystemUpstreamResolvesLocalhost) {
    co_await m_loop->co_submit();
    auto upstream_res = create_upstream({"system://"});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();

    for (utils::TransportProtocol proto : {utils::TP_UDP, utils::TP_TCP}) {
        for (ldns_rr_type type : {LDNS_RR_TYPE_A, LDNS_RR_TYPE_AAAA}) {
            TestError error = co_await resolve_localhost(*upstream_res.value(), proto, type);
            ASSERT_FALSE(error) << *error;
        }
    }
}

// `DnsQueryEx()` can't query a class other than IN
TEST_F(UpstreamTest, SystemUpstreamRejectsNonInClass) {
    co_await m_loop->co_submit();
    auto upstream_res = create_upstream({"system://"});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();

    ldns_pkt_ptr request = create_query("version.bind.", LDNS_RR_TYPE_TXT, LDNS_RR_CLASS_CH);
    auto reply = co_await upstream_res.value()->exchange(request.get());
    ASSERT_FALSE(reply.has_error()) << reply.error()->str();
    ASSERT_EQ(LDNS_RCODE_NOTIMPL, ldns_pkt_get_rcode(reply.value().get()));
    ASSERT_EQ(REQUEST_ID, ldns_pkt_id(reply.value().get()));
}

// A name `DnsQueryEx()` can't take as is fails without querying anything
TEST_F(UpstreamTest, SystemUpstreamRejectsUnrepresentableName) {
    co_await m_loop->co_submit();
    auto upstream_res = create_upstream({"system://"});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();

    ldns_pkt_ptr request = create_query("a\\.b.example.com.", LDNS_RR_TYPE_A);
    auto reply = co_await upstream_res.value()->exchange(request.get());
    ASSERT_TRUE(reply.has_error());
    ASSERT_EQ(DnsError::AE_ENCODE_ERROR, reply.error()->value()) << reply.error()->str();
}

// Many concurrent requests are all completed, each with its own reply.
TEST_F(UpstreamTest, SystemUpstreamConcurrentRequests) {
    co_await m_loop->co_submit();
    auto upstream_res = create_upstream({"system://"});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    Upstream &upstream = *upstream_res.value();

    static constexpr size_t COUNT = 32;
    auto errors = co_await parallel_run_n(COUNT, [&upstream](size_t i) {
        return resolve_localhost(upstream, (i % 2 == 0) ? utils::TP_UDP : utils::TP_TCP,
                (i % 4 < 2) ? LDNS_RR_TYPE_A : LDNS_RR_TYPE_AAAA);
    });
    co_await check_all_results(errors);
}

// Destroying the upstream completes the requests in flight with an error.
TEST_F(UpstreamTest, SystemUpstreamDestroyedWithRequestsInFlight) {
    co_await m_loop->co_submit();
    auto upstream_res = create_upstream({"system://"});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    UpstreamPtr upstream = std::move(upstream_res.value());

    static constexpr size_t COUNT = 8;
    std::vector<std::future<Upstream::ExchangeResult>> results;
    for (size_t i = 0; i < COUNT; ++i) {
        results.emplace_back(coro::to_future(exchange_name(upstream.get(), unique_name(i), LDNS_RR_TYPE_A)));
    }
    // The asynchronous completions are delivered via the event loop, which is busy running this test,
    // so only the queries that `DnsQueryEx()` completed synchronously (if any) can have completed by now.
    std::vector<bool> pending;
    for (auto &result : results) {
        pending.push_back(result.wait_for(std::chrono::seconds{0}) != std::future_status::ready);
    }
    if (std::find(pending.begin(), pending.end(), true) == pending.end()) {
        GTEST_SKIP() << "All the queries have completed synchronously";
    }
    upstream.reset();

    for (size_t i = 0; i < COUNT; ++i) {
        ASSERT_EQ(std::future_status::ready, results[i].wait_for(std::chrono::seconds{0}));
        Upstream::ExchangeResult r = results[i].get();
        if (pending[i]) {
            ASSERT_TRUE(r.has_error());
            ASSERT_EQ(DnsError::AE_SHUTTING_DOWN, r.error()->value()) << r.error()->str();
        }
    }
}

// A coroutine resumed by the destructor may immediately send another request (e.g. a caller that
// retries on `AE_SHUTTING_DOWN`). Such requests must be rejected instead of modifying the request
// map while it's being drained.
TEST_F(UpstreamTest, SystemUpstreamRejectsRequestsSentWhileDestroying) {
    co_await m_loop->co_submit();
    RetryState state;
    auto upstream_res = create_upstream({"system://"});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    UpstreamPtr upstream = std::move(upstream_res.value());

    std::future<void> completion = coro::to_future(exchange_and_retry(upstream.get(), state));
    // If the first query completed synchronously, the retry was sent before the destruction started.
    if (state.first_completed) {
        GTEST_SKIP() << "The first query has completed synchronously";
    }

    state.destroying = true;
    upstream.reset();

    ASSERT_EQ(std::future_status::ready, completion.wait_for(std::chrono::seconds{0}));
    ASSERT_TRUE(state.retried_during_destruction);
    ASSERT_TRUE(state.retry_result.has_value());
    ASSERT_TRUE(state.retry_result->has_error());
    ASSERT_EQ(DnsError::AE_SHUTTING_DOWN, state.retry_result->error()->value()) << state.retry_result->error()->str();
    // The error is produced by `send()`'s guard, not by the destructor completing a request that
    // was accepted: an accepted retry would carry the destructor's message-less error.
    ASSERT_NE(std::string::npos, state.retry_result->error()->str().find("being destroyed"))
            << state.retry_result->error()->str();
}

// `DnsQueryEx()` completes queries for IP address literals synchronously, without invoking the
// completion callback. This covers the request completion from `await_ready()`.
TEST_F(UpstreamTest, SystemUpstreamCompletesAddressQueriesSynchronously) {
    co_await m_loop->co_submit();
    auto upstream_res = create_upstream({"system://"});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    UpstreamPtr upstream = std::move(upstream_res.value());

    // The event loop is busy running this test, so an asynchronous query can't complete here.
    std::future<Upstream::ExchangeResult> completion =
            coro::to_future(exchange_name(upstream.get(), "1.1.1.1", LDNS_RR_TYPE_A));
    ASSERT_EQ(std::future_status::ready, completion.wait_for(std::chrono::seconds{0}))
            << "DnsQueryEx() hasn't completed the address query synchronously";

    Upstream::ExchangeResult result = completion.get();
    ASSERT_FALSE(result.has_error()) << result.error()->str();
    ASSERT_NE(nullptr, result.value());
}

// The requests that take longer than the timeout complete with an error, and the upstream keeps working.
TEST_F(UpstreamTest, SystemUpstreamTimesOut) {
    co_await m_loop->co_submit();
    auto upstream_res = create_upstream({"system://"}, Millis{1});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    Upstream &upstream = *upstream_res.value();

    static constexpr size_t COUNT = 8;
    auto all_of = parallel::all_of<Upstream::ExchangeResult>();
    for (size_t i = 0; i < COUNT; ++i) {
        all_of.add(exchange_name(&upstream, unique_name(i), LDNS_RR_TYPE_A));
    }
    std::vector<Upstream::ExchangeResult> results = co_await all_of;
    size_t timed_out = 0;
    for (const auto &r : results) {
        if (r.has_error() && r.error()->value() == DnsError::AE_TIMED_OUT) {
            ++timed_out;
        }
    }
    if (timed_out == 0) {
        GTEST_SKIP() << "All the queries have completed within the timeout";
    }

    TestError error = co_await resolve_localhost(upstream, utils::TP_UDP, LDNS_RR_TYPE_A);
    ASSERT_FALSE(error) << *error;
}

// Integration-only: a real query via the interface that routes to the public internet.
TEST_F(UpstreamTest, SystemUpstreamResolvesViaInterfaceIndex) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    std::optional<DWORD> index = best_interface_index(inet_addr("8.8.8.8"));
    ASSERT_TRUE(index.has_value());
    auto upstream_res = create_upstream({AG_FMT("system://{}", *index)});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
    TestError error = co_await check_upstream(*upstream_res.value(), upstream_res.value()->options().address);
    ASSERT_FALSE(error) << *error;
}

// Integration-only: a nonexistent name gets NXDOMAIN with an SOA record.
TEST_F(UpstreamTest, SystemUpstreamNxdomain) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    // The system resolver may take over 10 seconds to give up on a nonexistent name
    auto upstream_res = create_upstream({"system://"}, Secs{30});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();

    for (utils::TransportProtocol proto : {utils::TP_UDP, utils::TP_TCP}) {
        DnsMessageInfo info{.proto = proto};
        ldns_pkt_ptr request =
                create_query(AG_FMT("nx-{}.adguard-dnslibs-test.com.", GetTickCount64()).c_str(), LDNS_RR_TYPE_A);
        auto reply = co_await upstream_res.value()->exchange(request.get(), &info);
        ASSERT_FALSE(reply.has_error()) << reply.error()->str();
        ASSERT_EQ(LDNS_RCODE_NXDOMAIN, ldns_pkt_get_rcode(reply.value().get()));
        ASSERT_FALSE(rdata_of_type(ldns_pkt_authority(reply.value().get()), LDNS_RR_TYPE_SOA).empty());
    }
}

// Integration-only: the records assembled from the `DnsQueryEx()` structures are the same as the ones
// a plain DNS server returns, so the structure fields are interpreted correctly.
TEST_F(UpstreamTest, SystemUpstreamMatchesPlainDns) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    auto system_res = create_upstream({"system://"});
    ASSERT_FALSE(system_res.has_error()) << system_res.error()->str();
    auto plain_res = create_upstream({"8.8.8.8"});
    ASSERT_FALSE(plain_res.has_error()) << plain_res.error()->str();

    struct Case {
        const char *name;
        ldns_rr_type type;
    };
    for (const Case &c : {
                 Case{"gmail.com.", LDNS_RR_TYPE_MX},
                 Case{"gmail.com.", LDNS_RR_TYPE_TXT},
                 Case{"_caldavs._tcp.gmail.com.", LDNS_RR_TYPE_SRV},
                 Case{"cloudflare.com.", LDNS_RR_TYPE_DNSKEY},
                 Case{"cloudflare.com.", LDNS_RR_TYPE_DS},
         }) {
        ldns_pkt_ptr request = create_query(c.name, c.type);
        auto system_reply = co_await system_res.value()->exchange(request.get());
        ASSERT_FALSE(system_reply.has_error()) << c.name << ": " << system_reply.error()->str();
        auto plain_reply = co_await plain_res.value()->exchange(request.get());
        ASSERT_FALSE(plain_reply.has_error()) << c.name << ": " << plain_reply.error()->str();
        std::vector<std::string> expected = rdata_of_type(ldns_pkt_answer(plain_reply.value().get()), c.type);
        ASSERT_FALSE(expected.empty()) << c.name;
        ASSERT_EQ(expected, rdata_of_type(ldns_pkt_answer(system_reply.value().get()), c.type)) << c.name;
    }
}

// Integration-only: with the DO bit, the signatures are returned too.
TEST_F(UpstreamTest, SystemUpstreamReturnsSignatures) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    auto upstream_res = create_upstream({"system://"});
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();

    ldns_pkt_ptr request = create_query("cloudflare.com.", LDNS_RR_TYPE_DNSKEY);
    ldns_pkt_set_edns_udp_size(request.get(), 1232);
    ldns_pkt_set_edns_do(request.get(), true);
    auto reply = co_await upstream_res.value()->exchange(request.get());
    ASSERT_FALSE(reply.has_error()) << reply.error()->str();
    const ldns_rr_list *answer = ldns_pkt_answer(reply.value().get());
    bool found = false;
    for (size_t i = 0; i < ldns_rr_list_rr_count(answer); ++i) {
        const ldns_rr *rr = ldns_rr_list_rr(answer, i);
        if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_RRSIG) {
            continue;
        }
        found = true;
        ASSERT_EQ(LDNS_RR_TYPE_DNSKEY, ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(rr)));
        // Swapped byte orders would make these way off
        auto now = (uint32_t) time(nullptr);
        uint32_t expiration = ldns_rdf2native_time_t(ldns_rr_rrsig_expiration(rr));
        uint32_t inception = ldns_rdf2native_time_t(ldns_rr_rrsig_inception(rr));
        static constexpr uint32_t YEAR = 366 * 24 * 3600;
        ASSERT_LT(inception, now + 3600);
        ASSERT_GT(expiration, now - 3600);
        ASSERT_LT(expiration, now + YEAR);
        ASSERT_GT(inception, now - YEAR);
        AllocatedPtr<char> signer{ldns_rdf2str(ldns_rr_rrsig_signame(rr))};
        ASSERT_STREQ("cloudflare.com.", signer.get());
    }
    ASSERT_TRUE(found);
}

} // namespace ag::dns::upstream::test
