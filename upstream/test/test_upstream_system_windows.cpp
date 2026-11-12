#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <vector>

#include <magic_enum/magic_enum.hpp>

// The fixture includes `winsock2.h` with the required Windows macros, so it must come before `iphlpapi.h`.
#include "upstream_test_fixture.h"

#include <iphlpapi.h>

#include "../upstream_system_windows.h"

namespace ag::dns::upstream::test {

static constexpr uint16_t REQUEST_ID = 0x1234;

// `DnsQueryRaw()` only exists on Windows 11 23H2 and Windows Server 2025 and later. Skip the test
// instead of failing it on an older system, but fail it if the upstream can't be created for
// another reason.
#define REQUIRE_DNS_QUERY_RAW(upstream_res)                                                                            \
    do {                                                                                                               \
        if ((upstream_res).has_error()) {                                                                              \
            const auto &error = (upstream_res).error();                                                                \
            if (error->value() == ag::dns::UpstreamFactory::UpstreamCreateError::AE_INIT_FAILED                        \
                    && error->str().find("DnsQueryRaw") != std::string::npos) {                                        \
                GTEST_SKIP() << "DnsQueryRaw() is not available on this Windows version";                              \
            }                                                                                                          \
            FAIL() << "Failed to create the system upstream: " << error->str();                                        \
        }                                                                                                              \
    } while (0)

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

// The record data of the records of a type, sorted.
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

static std::vector<ldns_rr_type> types_of(const ldns_rr_list *list) {
    std::vector<ldns_rr_type> result;
    for (size_t i = 0; i < ldns_rr_list_rr_count(list); ++i) {
        result.push_back(ldns_rr_get_type(ldns_rr_list_rr(list, i)));
    }
    return result;
}

// Checks that the reply is a NOERROR answer to the request.
static TestError check_reply_header(const ldns_pkt &reply) {
    if (ldns_pkt_get_rcode(&reply) != LDNS_RCODE_NOERROR) {
        return AG_FMT("Unexpected rcode: {}", (int) ldns_pkt_get_rcode(&reply));
    }
    if (ldns_pkt_id(&reply) != REQUEST_ID) {
        return AG_FMT("Reply ID {} doesn't match the request ID", ldns_pkt_id(&reply));
    }
    if (!ldns_pkt_qr(&reply)) {
        return "The reply doesn't have the QR bit set";
    }
    return std::nullopt;
}

// Returns the DNS hostname of the local machine with a trailing dot. A query for it is answered
// by the DNS Client itself, without the network, so its answer doesn't depend on the hosts file or
// the configured resolver. `GetComputerNameW()` isn't used: it returns the legacy NetBIOS name,
// while the DNS Client knows the machine by its DNS hostname (`GetComputerNameExW()`).
static std::string local_machine_name() {
    wchar_t name[256];
    DWORD size = sizeof(name) / sizeof(name[0]);
    if (!GetComputerNameExW(ComputerNameDnsHostname, name, &size)) {
        return {};
    }
    return AG_FMT("{}.", utils::from_wstring(std::wstring_view{name, size}));
}

// Queries `name` and checks the reply. With `require_answer`, the answer section must have a record
// of `type`. The A answer is required, while the AAAA answer may be empty on an IPv4-only machine.
static coro::Task<TestError> resolve_name(
        Upstream &upstream, utils::TransportProtocol proto, std::string name, ldns_rr_type type, bool require_answer) {
    DnsMessageInfo info{.proto = proto};
    ldns_pkt_ptr request = create_query(name.c_str(), type);
    auto reply = co_await upstream.exchange(request.get(), &info);
    if (reply.has_error()) {
        co_return AG_FMT("proto={}: {}", magic_enum::enum_name(proto), reply.error()->str());
    }
    if (TestError error = check_reply_header(*reply.value())) {
        co_return AG_FMT("proto={}: {}", magic_enum::enum_name(proto), *error);
    }
    if (require_answer && rdata_of_type(ldns_pkt_answer(reply.value().get()), type).empty()) {
        co_return AG_FMT(
                "proto={}: no records of type {} in the answer section", magic_enum::enum_name(proto), (int) type);
    }
    co_return std::nullopt;
}

// A name nobody has, so that the query takes a while
static std::string unique_name(size_t i) {
    return AG_FMT("ag-dnslibs-test-{}-{}.invalid.", i, GetTickCount64());
}

static coro::Task<Upstream::ExchangeResult> exchange_name(
        Upstream *upstream, std::string name, ldns_rr_type type, bool dnssec_ok = false) {
    ldns_pkt_ptr request = create_query(name.c_str(), type);
    ldns_pkt_set_edns_do(request.get(), dnssec_ok);
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

/** Serializes a packet into the wire format that `DnsQueryRaw()` returns. */
static std::vector<uint8_t> to_wire(const ldns_pkt *pkt) {
    uint8_t *data = nullptr;
    size_t size = 0;
    if (ldns_pkt2wire(&data, pkt, &size) != LDNS_STATUS_OK) {
        return {};
    }
    AllocatedPtr<uint8_t> guard{data};
    return {data, data + size};
}

/**
 * Adds the 2-byte length field that `DnsQueryRaw()` puts in front of the reply to a
 * `DNS_PROTOCOL_TCP` query.
 */
static std::vector<uint8_t> to_tcp_frame(const std::vector<uint8_t> &message) {
    std::vector<uint8_t> framed;
    framed.reserve(message.size() + 2);
    framed.push_back(uint8_t(message.size() >> 8));
    framed.push_back(uint8_t(message.size()));
    framed.insert(framed.end(), message.begin(), message.end());
    return framed;
}

/** Makes a NOERROR reply to `request` with a different ID, as `DnsQueryRaw()` returns it. */
static ldns_pkt_ptr make_reply(const ldns_pkt *request) {
    ldns_pkt *reply = ldns_pkt_new();
    ldns_pkt_set_id(reply, uint16_t(ldns_pkt_id(request) + 1));
    ldns_pkt_set_qr(reply, true);
    ldns_pkt_set_rd(reply, true);
    ldns_pkt_set_ra(reply, true);
    ldns_pkt_set_rcode(reply, LDNS_RCODE_NOERROR);
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(request), 0);
    ldns_pkt_push_rr(reply, LDNS_SECTION_QUESTION, ldns_rr_clone(question));
    return ldns_pkt_ptr{reply};
}

/** Parses a record in the presentation format and appends it to a section of `reply`. */
static void add_rr(ldns_pkt *reply, ldns_pkt_section section, std::string_view text) {
    ldns_rr *rr = nullptr;
    ldns_status status = ldns_rr_new_frm_str(&rr, std::string{text}.c_str(), 0, nullptr, nullptr);
    EXPECT_EQ(LDNS_STATUS_OK, status) << text;
    if (rr != nullptr) {
        ldns_pkt_push_rr(reply, section, rr);
    }
}

/** Parses a record given in wire format and appends it to a section of `reply`. */
static void add_wire_rr(ldns_pkt *reply, ldns_pkt_section section, const std::vector<uint8_t> &wire_rr) {
    ldns_rr *rr = nullptr;
    size_t pos = 0;
    ldns_status status = ldns_wire2rr(&rr, wire_rr.data(), wire_rr.size(), &pos, section);
    EXPECT_EQ(LDNS_STATUS_OK, status);
    EXPECT_EQ(wire_rr.size(), pos);
    if (rr != nullptr) {
        ldns_pkt_push_rr(reply, section, rr);
    }
}

/** Runs `make_system_reply()` on a serialized reply, framing it for TCP if needed. */
static Upstream::ExchangeResult make_reply_from(const ldns_pkt *request, const ldns_pkt *reply, bool tcp = false) {
    std::vector<uint8_t> wire = to_wire(reply);
    if (tcp) {
        wire = to_tcp_frame(wire);
    }
    return make_system_reply(request, {wire.data(), wire.size()}, tcp);
}

TEST(SystemUpstreamReplyTest, RestoresTheRequestId) {
    ldns_pkt_ptr request = create_query("example.com.", LDNS_RR_TYPE_A);
    ldns_pkt_ptr reply = make_reply(request.get());
    ASSERT_NE(ldns_pkt_id(request.get()), ldns_pkt_id(reply.get()));
    add_rr(reply.get(), LDNS_SECTION_ANSWER, "example.com. 300 IN A 1.2.3.4");

    auto result = make_reply_from(request.get(), reply.get());
    ASSERT_FALSE(result.has_error()) << result.error()->str();
    const ldns_pkt *parsed = result.value().get();
    ASSERT_EQ(REQUEST_ID, ldns_pkt_id(parsed));
    ASSERT_TRUE(ldns_pkt_qr(parsed));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(parsed));
    ASSERT_EQ((std::vector<std::string>{"1.2.3.4"}), rdata_of_type(ldns_pkt_answer(parsed), LDNS_RR_TYPE_A));
}

// The reply is passed through as is: the header flags, the sections, the record types that
// `DnsQueryEx()` couldn't represent, and EDNS are preserved, including the TC bit of a truncated
// UDP response.
TEST(SystemUpstreamReplyTest, PassesTheReplyThrough) {
    static constexpr uint16_t UDP_SIZE = 1232;
    static constexpr uint8_t EDNS_OPTION[] = {0x00, 0x0a, 0x00, 0x02, 0xab, 0xcd}; // COOKIE, truncated

    ldns_pkt_ptr request = create_query("example.com.", LDNS_RR_TYPE_HTTPS);
    ldns_pkt_set_edns_udp_size(request.get(), UDP_SIZE);

    ldns_pkt_ptr reply = make_reply(request.get());
    ldns_pkt_set_tc(reply.get(), true);
    ldns_pkt_set_ad(reply.get(), true);
    // example.com. 300 IN HTTPS 1 . alpn=h2,h3
    static const std::vector<uint8_t> HTTPS_RR = {
            0x07,
            'e',
            'x',
            'a',
            'm',
            'p',
            'l',
            'e',
            0x03,
            'c',
            'o',
            'm',
            0x00, // owner
            0x00,
            0x41, // type
            0x00,
            0x01, // class
            0x00,
            0x00,
            0x01,
            0x2c, // TTL
            0x00,
            0x0d, // RDLENGTH
            0x00,
            0x01, // priority
            0x00, // target
            0x00,
            0x01,
            0x00,
            0x06,
            0x02,
            'h',
            '2',
            0x02,
            'h',
            '3', // alpn=h2,h3
    };
    add_wire_rr(reply.get(), LDNS_SECTION_ANSWER, HTTPS_RR);
    add_rr(reply.get(), LDNS_SECTION_ANSWER, "example.com. 300 IN CAA 0 issue \"letsencrypt.org\"");
    add_rr(reply.get(), LDNS_SECTION_AUTHORITY, "example.com. 300 IN NS ns.example.com.");
    add_rr(reply.get(), LDNS_SECTION_ADDITIONAL, "ns.example.com. 300 IN A 9.9.9.9");
    ldns_pkt_set_edns_udp_size(reply.get(), UDP_SIZE);
    ldns_pkt_set_edns_do(reply.get(), true);
    ldns_pkt_set_edns_data(reply.get(), ldns_rdf_new_frm_data(LDNS_RDF_TYPE_UNKNOWN, sizeof(EDNS_OPTION), EDNS_OPTION));

    auto result = make_reply_from(request.get(), reply.get());
    ASSERT_FALSE(result.has_error()) << result.error()->str();
    const ldns_pkt *parsed = result.value().get();
    ASSERT_EQ(REQUEST_ID, ldns_pkt_id(parsed));
    ASSERT_TRUE(ldns_pkt_qr(parsed));
    ASSERT_TRUE(ldns_pkt_tc(parsed));
    ASSERT_TRUE(ldns_pkt_ad(parsed));
    ASSERT_EQ(LDNS_RCODE_NOERROR, ldns_pkt_get_rcode(parsed));
    ASSERT_EQ(1, ldns_pkt_qdcount(parsed));
    ASSERT_EQ((std::vector<ldns_rr_type>{LDNS_RR_TYPE_HTTPS, LDNS_RR_TYPE_CAA}), types_of(ldns_pkt_answer(parsed)));
    ASSERT_EQ(
            "example.com.\t300\tIN\tHTTPS\t1 . alpn=h2,h3", rr_to_string(ldns_rr_list_rr(ldns_pkt_answer(parsed), 0)));
    ASSERT_EQ(1, ldns_pkt_nscount(parsed));
    ASSERT_EQ(
            (std::vector<std::string>{"ns.example.com."}), rdata_of_type(ldns_pkt_authority(parsed), LDNS_RR_TYPE_NS));
    // The OPT record isn't in the additional section: ldns keeps it in the packet's EDNS fields
    ASSERT_EQ(1, ldns_pkt_arcount(parsed));
    ASSERT_EQ((std::vector<std::string>{"9.9.9.9"}), rdata_of_type(ldns_pkt_additional(parsed), LDNS_RR_TYPE_A));
    ASSERT_TRUE(ldns_pkt_edns_do(parsed));
    ASSERT_EQ(UDP_SIZE, ldns_pkt_edns_udp_size(parsed));
    const ldns_rdf *edns_data = ldns_pkt_edns_data(parsed);
    ASSERT_NE(nullptr, edns_data);
    ASSERT_EQ(sizeof(EDNS_OPTION), ldns_rdf_size(edns_data));
    ASSERT_EQ(0, std::memcmp(EDNS_OPTION, ldns_rdf_data(edns_data), sizeof(EDNS_OPTION)));
}

TEST(SystemUpstreamReplyTest, ParsesTcpFramedReply) {
    ldns_pkt_ptr request = create_query("example.com.", LDNS_RR_TYPE_A);
    ldns_pkt_ptr reply = make_reply(request.get());
    add_rr(reply.get(), LDNS_SECTION_ANSWER, "example.com. 300 IN A 1.2.3.4");

    auto result = make_reply_from(request.get(), reply.get(), true);
    ASSERT_FALSE(result.has_error()) << result.error()->str();
    ASSERT_EQ((std::vector<std::string>{"1.2.3.4"}),
            rdata_of_type(ldns_pkt_answer(result.value().get()), LDNS_RR_TYPE_A));
}

TEST(SystemUpstreamReplyTest, RejectsMalformedTcpFrame) {
    ldns_pkt_ptr request = create_query("example.com.", LDNS_RR_TYPE_A);
    ldns_pkt_ptr reply = make_reply(request.get());
    add_rr(reply.get(), LDNS_SECTION_ANSWER, "example.com. 300 IN A 1.2.3.4");
    std::vector<uint8_t> wire = to_wire(reply.get());
    ASSERT_FALSE(wire.empty());

    // The length field alone, without the message
    std::array<uint8_t, 2> too_short{0x00, 0x01};
    auto result = make_system_reply(request.get(), {too_short.data(), too_short.size()}, true);
    ASSERT_TRUE(result.has_error());
    ASSERT_EQ(DnsError::AE_DECODE_ERROR, result.error()->value()) << result.error()->str();

    // The declared length doesn't match the message length
    std::vector<uint8_t> wrong_length = to_tcp_frame(wire);
    wrong_length[1] = uint8_t(wrong_length[1] + 1);
    result = make_system_reply(request.get(), {wrong_length.data(), wrong_length.size()}, true);
    ASSERT_TRUE(result.has_error());
    ASSERT_EQ(DnsError::AE_DECODE_ERROR, result.error()->value()) << result.error()->str();

    // An unframed message
    result = make_system_reply(request.get(), {wire.data(), wire.size()}, true);
    ASSERT_TRUE(result.has_error());
    ASSERT_EQ(DnsError::AE_DECODE_ERROR, result.error()->value()) << result.error()->str();
}

TEST(SystemUpstreamReplyTest, RejectsMalformedReply) {
    static constexpr uint8_t GARBAGE[] = {0x12, 0x34, 0x01};
    ldns_pkt_ptr request = create_query("example.com.", LDNS_RR_TYPE_A);
    auto result = make_system_reply(request.get(), {GARBAGE, sizeof(GARBAGE)}, false);
    ASSERT_TRUE(result.has_error());
    ASSERT_EQ(DnsError::AE_DECODE_ERROR, result.error()->value()) << result.error()->str();
}

// The DNS Client may answer a query without DO from the cache entry made for a DO query, which has
// the signatures, so the DNSSEC records that weren't asked for are dropped.
TEST(SystemUpstreamReplyTest, DropsUnrequestedDnssecRecordsWithoutDo) {
    ldns_pkt_ptr request = create_query("example.com.", LDNS_RR_TYPE_A);
    ldns_pkt_ptr reply = make_reply(request.get());
    add_rr(reply.get(), LDNS_SECTION_ANSWER, "example.com. 300 IN A 1.2.3.4");
    add_rr(reply.get(), LDNS_SECTION_ANSWER,
            "example.com. 300 IN RRSIG A 8 2 300 20300101000000 20200101000000 12345 example.com. AQIDBA==");
    add_rr(reply.get(), LDNS_SECTION_ANSWER,
            "example.com. 300 IN DS 12345 8 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899");
    add_rr(reply.get(), LDNS_SECTION_AUTHORITY, "example.com. 300 IN NSEC ns.example.com. A RRSIG NSEC");
    add_rr(reply.get(), LDNS_SECTION_AUTHORITY,
            "example.com. 300 IN RRSIG NSEC 8 2 300 20300101000000 20200101000000 12345 example.com. AQIDBA==");
    add_rr(reply.get(), LDNS_SECTION_ADDITIONAL, "ns.example.com. 300 IN A 9.9.9.9");

    auto result = make_reply_from(request.get(), reply.get());
    ASSERT_FALSE(result.has_error()) << result.error()->str();
    const ldns_pkt *parsed = result.value().get();
    ASSERT_EQ(std::vector{LDNS_RR_TYPE_A}, types_of(ldns_pkt_answer(parsed)));
    ASSERT_EQ(std::vector<ldns_rr_type>{}, types_of(ldns_pkt_authority(parsed)));
    ASSERT_EQ((std::vector<std::string>{"9.9.9.9"}), rdata_of_type(ldns_pkt_additional(parsed), LDNS_RR_TYPE_A));
}

// Without DO, the DNSSEC records of the asked type are still returned, and only them.
TEST(SystemUpstreamReplyTest, KeepsRequestedDnssecRecordsWithoutDo) {
    ldns_pkt_ptr request = create_query("example.com.", LDNS_RR_TYPE_DS);
    ldns_pkt_ptr reply = make_reply(request.get());
    add_rr(reply.get(), LDNS_SECTION_ANSWER, "example.com. 300 IN A 1.2.3.4");
    add_rr(reply.get(), LDNS_SECTION_ANSWER,
            "example.com. 300 IN RRSIG A 8 2 300 20300101000000 20200101000000 12345 example.com. AQIDBA==");
    add_rr(reply.get(), LDNS_SECTION_ANSWER,
            "example.com. 300 IN DS 12345 8 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899");
    add_rr(reply.get(), LDNS_SECTION_AUTHORITY, "example.com. 300 IN NSEC ns.example.com. A RRSIG NSEC");

    auto result = make_reply_from(request.get(), reply.get());
    ASSERT_FALSE(result.has_error()) << result.error()->str();
    const ldns_pkt *parsed = result.value().get();
    ASSERT_EQ((std::vector{LDNS_RR_TYPE_A, LDNS_RR_TYPE_DS}), types_of(ldns_pkt_answer(parsed)));
    ASSERT_EQ(std::vector<ldns_rr_type>{}, types_of(ldns_pkt_authority(parsed)));

    ldns_pkt_ptr any_request = create_query("example.com.", LDNS_RR_TYPE_ANY);
    result = make_reply_from(any_request.get(), reply.get());
    ASSERT_FALSE(result.has_error()) << result.error()->str();
    parsed = result.value().get();
    ASSERT_EQ((std::vector{LDNS_RR_TYPE_A, LDNS_RR_TYPE_RRSIG, LDNS_RR_TYPE_DS}), types_of(ldns_pkt_answer(parsed)));
    ASSERT_EQ(std::vector<ldns_rr_type>{}, types_of(ldns_pkt_authority(parsed)));
}

// With DO, all the DNSSEC records are returned.
TEST(SystemUpstreamReplyTest, KeepsDnssecRecordsWithDo) {
    ldns_pkt_ptr request = create_query("example.com.", LDNS_RR_TYPE_A);
    ldns_pkt_set_edns_do(request.get(), true);
    ldns_pkt_ptr reply = make_reply(request.get());
    add_rr(reply.get(), LDNS_SECTION_ANSWER, "example.com. 300 IN A 1.2.3.4");
    add_rr(reply.get(), LDNS_SECTION_ANSWER,
            "example.com. 300 IN RRSIG A 8 2 300 20300101000000 20200101000000 12345 example.com. AQIDBA==");
    add_rr(reply.get(), LDNS_SECTION_ANSWER,
            "example.com. 300 IN DS 12345 8 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899");
    add_rr(reply.get(), LDNS_SECTION_AUTHORITY, "example.com. 300 IN NSEC ns.example.com. A RRSIG NSEC");
    add_rr(reply.get(), LDNS_SECTION_AUTHORITY,
            "example.com. 300 IN RRSIG NSEC 8 2 300 20300101000000 20200101000000 12345 example.com. AQIDBA==");

    auto result = make_reply_from(request.get(), reply.get());
    ASSERT_FALSE(result.has_error()) << result.error()->str();
    const ldns_pkt *parsed = result.value().get();
    ASSERT_EQ((std::vector{LDNS_RR_TYPE_A, LDNS_RR_TYPE_RRSIG, LDNS_RR_TYPE_DS}), types_of(ldns_pkt_answer(parsed)));
    ASSERT_EQ((std::vector{LDNS_RR_TYPE_NSEC, LDNS_RR_TYPE_RRSIG}), types_of(ldns_pkt_authority(parsed)));
}

// The request is passed to `DnsQueryRaw()` as is: the header flags, the question, and the EDNS
// options must survive the serialization.
TEST(SystemUpstreamQueryTest, Wire) {
    static constexpr uint16_t UDP_SIZE = 1232;
    static constexpr uint8_t EDNS_OPTION[] = {0x00, 0x0a, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8}; // COOKIE

    ldns_pkt_ptr request = create_query("ExAmPle.com.", LDNS_RR_TYPE_HTTPS);
    ldns_pkt_set_cd(request.get(), true);
    ldns_pkt_set_ad(request.get(), true);
    ldns_pkt_set_edns_udp_size(request.get(), UDP_SIZE);
    ldns_pkt_set_edns_do(request.get(), true);
    ldns_pkt_set_edns_data(
            request.get(), ldns_rdf_new_frm_data(LDNS_RDF_TYPE_UNKNOWN, sizeof(EDNS_OPTION), EDNS_OPTION));

    std::optional<Uint8Vector> wire = system_query_wire(request.get(), false);
    ASSERT_TRUE(wire.has_value());
    ldns_pkt *raw_pkt = nullptr;
    ASSERT_EQ(LDNS_STATUS_OK, ldns_wire2pkt(&raw_pkt, wire->data(), wire->size()));
    ldns_pkt_ptr parsed{raw_pkt};
    ASSERT_EQ(REQUEST_ID, ldns_pkt_id(parsed.get()));
    ASSERT_TRUE(ldns_pkt_rd(parsed.get()));
    ASSERT_TRUE(ldns_pkt_cd(parsed.get()));
    ASSERT_TRUE(ldns_pkt_ad(parsed.get()));
    ASSERT_EQ(1, ldns_pkt_qdcount(parsed.get()));
    const ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(parsed.get()), 0);
    ASSERT_NE(nullptr, question);
    ASSERT_EQ(LDNS_RR_TYPE_HTTPS, ldns_rr_get_type(question));
    ASSERT_EQ(LDNS_RR_CLASS_IN, ldns_rr_get_class(question));
    AllocatedPtr<char> name{ldns_rdf2str(ldns_rr_owner(question))};
    ASSERT_NE(nullptr, name);
    ASSERT_STREQ("ExAmPle.com.", name.get());
    ASSERT_TRUE(ldns_pkt_edns_do(parsed.get()));
    ASSERT_EQ(UDP_SIZE, ldns_pkt_edns_udp_size(parsed.get()));
    const ldns_rdf *edns_data = ldns_pkt_edns_data(parsed.get());
    ASSERT_NE(nullptr, edns_data);
    ASSERT_EQ(sizeof(EDNS_OPTION), ldns_rdf_size(edns_data));
    ASSERT_EQ(0, std::memcmp(EDNS_OPTION, ldns_rdf_data(edns_data), sizeof(EDNS_OPTION)));

    // A TCP query is prefixed with the 2-byte length
    std::optional<Uint8Vector> framed = system_query_wire(request.get(), true);
    ASSERT_TRUE(framed.has_value());
    ASSERT_GE(framed->size(), 2);
    ASSERT_EQ(wire->size(), (size_t((*framed)[0]) << 8) | (*framed)[1]);
    ASSERT_EQ(*wire, Uint8Vector(framed->begin() + 2, framed->end()));
}

TEST(SystemUpstreamQueryTest, Options) {
    ldns_pkt_ptr request = create_query("example.com.", LDNS_RR_TYPE_A);
    ULONG64 options = system_query_options(request.get());
    // NetBIOS and multicast name resolution must be off: the DNS Client would stall on their
    // timeouts. Its local answers (the hosts file, `localhost`) are kept.
    ASSERT_TRUE(options & DNS_QUERY_NO_NETBT);
    ASSERT_TRUE(options & DNS_QUERY_NO_MULTICAST);
    ASSERT_FALSE(options & DNS_QUERY_NO_LOCAL_NAME);
    ASSERT_FALSE(options & DNS_QUERY_NO_HOSTS_FILE);
    ASSERT_FALSE(options & DNS_QUERY_NO_WIRE_QUERY);
    // The packet is passed as is: no name conversion
    ASSERT_FALSE(options & DNS_QUERY_TREAT_AS_FQDN);
    ASSERT_FALSE(options & DNS_QUERY_DISABLE_IDN_ENCODING);
    // The transport is specified by `DNS_QUERY_RAW_REQUEST::protocol`
    ASSERT_FALSE(options & DNS_QUERY_USE_TCP_ONLY);
    // Truncated UDP replies are passed through: the proxy truncates the reply for the client
    ASSERT_FALSE(options & DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE);
    // The DO and CD bits are in the packet, the options must not apply them on top of it
    ASSERT_FALSE(options & DNS_QUERY_DNSSEC_OK);
    ASSERT_FALSE(options & DNS_QUERY_DNSSEC_CHECKING_DISABLED);
    // The cached answers are used unless the DO bit is set
    ASSERT_FALSE(options & DNS_QUERY_BYPASS_CACHE);

    ldns_pkt_set_edns_do(request.get(), true);
    ldns_pkt_set_cd(request.get(), true);
    options = system_query_options(request.get());
    ASSERT_TRUE(options & DNS_QUERY_BYPASS_CACHE);
    ASSERT_FALSE(options & DNS_QUERY_DNSSEC_OK);
    ASSERT_FALSE(options & DNS_QUERY_DNSSEC_CHECKING_DISABLED);
    // The local answers are still used
    ASSERT_FALSE(options & DNS_QUERY_NO_LOCAL_NAME);
    ASSERT_FALSE(options & DNS_QUERY_NO_HOSTS_FILE);
    ASSERT_FALSE(options & DNS_QUERY_NO_WIRE_QUERY);

    ldns_pkt_set_edns_do(request.get(), false);
    options = system_query_options(request.get());
    ASSERT_FALSE(options & DNS_QUERY_BYPASS_CACHE);
}

TEST_F(UpstreamTest, SystemUpstreamInitAllInterfaces) {
    co_await m_loop->co_submit();
    auto upstream_res = create_upstream({"system://"});
    REQUIRE_DNS_QUERY_RAW(upstream_res);
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
}

TEST_F(UpstreamTest, SystemUpstreamInitInterfaceIndex) {
    co_await m_loop->co_submit();
    std::optional<DWORD> index = best_interface_index(htonl(INADDR_LOOPBACK));
    ASSERT_TRUE(index.has_value());
    auto upstream_res = create_upstream({AG_FMT("system://{}", *index)});
    REQUIRE_DNS_QUERY_RAW(upstream_res);
    ASSERT_FALSE(upstream_res.has_error()) << upstream_res.error()->str();
}

// The DNS Client answers a query for the local machine name itself, so this test doesn't depend on
// the hosts file or the configured resolver, and doesn't send anything over the network.
TEST_F(UpstreamTest, SystemUpstreamResolvesLocalMachineName) {
    co_await m_loop->co_submit();
    std::string name = local_machine_name();
    ASSERT_FALSE(name.empty()) << "Failed to get the local machine name";
    auto upstream_res = create_upstream({"system://"});
    REQUIRE_DNS_QUERY_RAW(upstream_res);

    for (utils::TransportProtocol proto : {utils::TP_UDP, utils::TP_TCP}) {
        TestError error = co_await resolve_name(*upstream_res.value(), proto, name, LDNS_RR_TYPE_A, true);
        ASSERT_FALSE(error) << *error;
        // The machine may have no IPv6 addresses, so the AAAA answer may be empty.
        error = co_await resolve_name(*upstream_res.value(), proto, name, LDNS_RR_TYPE_AAAA, false);
        ASSERT_FALSE(error) << *error;
    }
}

// Many concurrent requests are all completed, each with its own reply.
TEST_F(UpstreamTest, SystemUpstreamConcurrentRequests) {
    co_await m_loop->co_submit();
    std::string name = local_machine_name();
    ASSERT_FALSE(name.empty()) << "Failed to get the local machine name";
    auto upstream_res = create_upstream({"system://"});
    REQUIRE_DNS_QUERY_RAW(upstream_res);
    Upstream &upstream = *upstream_res.value();

    static constexpr size_t COUNT = 32;
    auto errors = co_await parallel_run_n(COUNT, [&upstream, &name](size_t i) {
        return resolve_name(upstream, (i % 2 == 0) ? utils::TP_UDP : utils::TP_TCP, name, LDNS_RR_TYPE_A, true);
    });
    co_await check_all_results(errors);
}

// Integration-only: destroying the upstream completes the requests in flight with an error. The
// queries are sent to the configured servers (they must not be answered before the destruction).
TEST_F(UpstreamTest, SystemUpstreamDestroyedWithRequestsInFlight) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    auto upstream_res = create_upstream({"system://"});
    REQUIRE_DNS_QUERY_RAW(upstream_res);
    UpstreamPtr upstream = std::move(upstream_res.value());

    static constexpr size_t COUNT = 8;
    std::vector<std::future<Upstream::ExchangeResult>> results;
    for (size_t i = 0; i < COUNT; ++i) {
        results.emplace_back(coro::to_future(exchange_name(upstream.get(), unique_name(i), LDNS_RR_TYPE_A)));
    }
    // The asynchronous completions are delivered via the event loop, which is busy running this test,
    // so none of the queries can have completed by now.
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

// Integration-only: a coroutine resumed by the destructor may immediately send another request (e.g.
// a caller that retries on `AE_SHUTTING_DOWN`). Such requests must be rejected instead of modifying
// the request map while it's being drained. The queries are sent to the configured servers.
TEST_F(UpstreamTest, SystemUpstreamRejectsRequestsSentWhileDestroying) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    RetryState state;
    auto upstream_res = create_upstream({"system://"});
    REQUIRE_DNS_QUERY_RAW(upstream_res);
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
    const Upstream::ExchangeResult &retry_result = state.retry_result.value();
    ASSERT_TRUE(retry_result.has_error());
    ASSERT_EQ(DnsError::AE_SHUTTING_DOWN, retry_result.error()->value()) << retry_result.error()->str();
    // The error is produced by `send()`'s guard, not by the destructor completing a request that
    // was accepted: an accepted retry would carry the destructor's message-less error.
    ASSERT_NE(std::string::npos, retry_result.error()->str().find("being destroyed")) << retry_result.error()->str();
}

// Integration-only: the requests that take longer than the timeout complete with an error, and the
// upstream keeps working. The nonexistent names are sent to the configured servers.
TEST_F(UpstreamTest, SystemUpstreamTimesOut) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    auto upstream_res = create_upstream({"system://"}, Millis{1});
    REQUIRE_DNS_QUERY_RAW(upstream_res);
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

    std::string name = local_machine_name();
    ASSERT_FALSE(name.empty()) << "Failed to get the local machine name";
    // The upstream that timed out still accepts and completes requests. The 1 ms timeout is too
    // short for the asynchronous completion of even a local answer, so the query may time out too.
    auto after = co_await exchange_name(&upstream, name, LDNS_RR_TYPE_A);
    if (after.has_error()) {
        ASSERT_EQ(DnsError::AE_TIMED_OUT, after.error()->value()) << after.error()->str();
    }

    // The timed-out requests were cancelled cleanly: the event loop and the DNS Client still work.
    auto recovery_res = create_upstream({"system://"});
    ASSERT_FALSE(recovery_res.has_error()) << recovery_res.error()->str();
    TestError error = co_await resolve_name(*recovery_res.value(), utils::TP_UDP, name, LDNS_RR_TYPE_A, true);
    ASSERT_FALSE(error) << *error;
}

// Integration-only: a real query via the interface that routes to the public internet.
TEST_F(UpstreamTest, SystemUpstreamResolvesViaInterfaceIndex) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    IPAddr ip{};
    ASSERT_EQ(1, InetPtonA(AF_INET, "8.8.8.8", &ip));
    std::optional<DWORD> index = best_interface_index(ip);
    ASSERT_TRUE(index.has_value());
    auto upstream_res = create_upstream({AG_FMT("system://{}", *index)});
    REQUIRE_DNS_QUERY_RAW(upstream_res);
    TestError error = co_await check_upstream(*upstream_res.value(), upstream_res.value()->options().address);
    ASSERT_FALSE(error) << *error;
}

// Integration-only: a nonexistent name gets NXDOMAIN with an SOA record.
TEST_F(UpstreamTest, SystemUpstreamNxdomain) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    // The system resolver may take over 10 seconds to give up on a nonexistent name
    auto upstream_res = create_upstream({"system://"}, Secs{30});
    REQUIRE_DNS_QUERY_RAW(upstream_res);

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

// Integration-only: the records of the raw reply are the same as the ones a plain DNS server
// returns.
TEST_F(UpstreamTest, SystemUpstreamMatchesPlainDns) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    auto system_res = create_upstream({"system://"});
    REQUIRE_DNS_QUERY_RAW(system_res);
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
                 Case{"tls-ech.dev.", LDNS_RR_TYPE_HTTPS},
                 Case{"cloudflare.com.", LDNS_RR_TYPE_CAA},
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
        std::vector<std::string> actual = rdata_of_type(ldns_pkt_answer(system_reply.value().get()), c.type);
        ASSERT_EQ(expected, actual) << c.name;
    }
}

// Integration-only: with the DO bit, the signatures are returned too.
TEST_F(UpstreamTest, SystemUpstreamReturnsSignatures) {
    REQUIRE_INTEGRATION();
    co_await m_loop->co_submit();
    auto upstream_res = create_upstream({"system://"});
    REQUIRE_DNS_QUERY_RAW(upstream_res);

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
