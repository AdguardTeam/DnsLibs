#ifdef _WIN32
#include <windows.h>
#endif

#include <ag_dns.h>

#include <ldns/ldns.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT(cond) do {                                 \
    if (!(cond)) {                                        \
        fprintf(stderr,                                   \
                "\n\t%s:%d:%s() assertion (%s) failed\n", \
                __FILE__, __LINE__, __func__, #cond);     \
        exit(1);                                          \
    }                                                     \
} while (0)

static bool on_req_called = false;
static bool expect_blocked_request = false;
static void on_req(const ag_dns_request_processed_event *event) {
    on_req_called = true;
    ASSERT(0 == strcmp(event->domain, "example.org."));
    ASSERT(event->answer);
    ASSERT(event->error == NULL);
    ASSERT(event->type);
    ASSERT(event->status);
    if (!expect_blocked_request) {
        ASSERT(event->elapsed > 0);
        ASSERT(event->upstream_id);
        ASSERT(*event->upstream_id == 42);
    } else {
        ASSERT(event->elapsed >= 0);
        ASSERT(event->upstream_id == NULL);
    }
}

static bool on_cert_called = false;
static ag_certificate_verification_result on_cert(const ag_certificate_verification_event *event) {
    on_cert_called = true;
    ASSERT(event->certificate.data);
    ASSERT(event->certificate.size > 0);
    for (size_t i = 0; i < event->chain.size; ++i) {
        ASSERT(event->chain.data[i].data);
        ASSERT(event->chain.data[i].size > 0);
    }
    return AGCVR_OK;
}

static void on_log(void *arg, ag_log_level level, const char *message, uint32_t length) {
    ASSERT((uintptr_t) arg == 42);
    fprintf(stderr, "on_log: (%d) %.*s\n", (int) level, (int) length, message);
}

static void test_proxy() {
    // Reset global flags at the beginning of the test
    on_req_called = false;
    on_cert_called = false;
    
    const char *version = ag_get_capi_version();
    ASSERT(version);
    ASSERT(strlen(version));

    ag_set_log_callback(on_log, (void *) (uintptr_t) 42);

    ag_dnsproxy_settings *settings = ag_dnsproxy_settings_get_default();

    ASSERT(settings->fallback_domains.size > 0);
    ASSERT(settings->fallback_domains.data);

    ASSERT(settings->upstreams.data == NULL);
    ASSERT(settings->upstreams.size == 0);

    ag_upstream_options upstream = {
            .address = "tls://1.1.1.1",
            .id = 42,
    };

    settings->upstreams.data = &upstream;
    settings->upstreams.size = 1;

    ag_dnsproxy_events events = {0};
    events.on_request_processed = on_req;
    events.on_certificate_verification = on_cert;

    ag_dnsproxy_init_result result;
    const char *message = NULL;
    ag_dnsproxy *proxy = ag_dnsproxy_init(settings, &events, &result, &message);
    ASSERT(proxy);
    ASSERT(result == AGDPIR_OK);
    ASSERT(message == NULL);

    ag_dnsproxy_settings *actual_settings = ag_dnsproxy_get_settings(proxy);
    ASSERT(actual_settings);
    ASSERT(actual_settings->upstreams.data[0].id == settings->upstreams.data[0].id);
    ag_dnsproxy_settings_free(actual_settings);

    memset(&settings->upstreams, 0, sizeof(settings->upstreams));
    ag_dnsproxy_settings_free(settings);

    ldns_pkt *query = ldns_pkt_query_new(ldns_dname_new_frm_str("example.org"),
                                         LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    ag_buffer msg = {0};
    size_t out_size;
    ASSERT(LDNS_STATUS_OK == ldns_pkt2wire(&msg.data, query, &out_size));
    msg.size = out_size;

    ag_buffer res = ag_dnsproxy_handle_message(proxy, msg, NULL);
    ASSERT(on_req_called);
    ASSERT(on_cert_called);

    ldns_pkt *response = NULL;
    ASSERT(LDNS_STATUS_OK == ldns_wire2pkt(&response, res.data, res.size));
    ASSERT(LDNS_RCODE_NOERROR == ldns_pkt_get_rcode(response));
    ASSERT(ldns_pkt_ancount(response) > 0);

    ag_dnsproxy_deinit(proxy);

    ldns_pkt_free(query);
    ldns_pkt_free(response);
    ag_buffer_free(res);
    LDNS_FREE(msg.data);
}

static void test_reapply_settings() {
    // Reset global flags at the beginning of the test
    on_req_called = false;
    on_cert_called = false;
    
    const char *version = ag_get_capi_version();
    ASSERT(version);
    ASSERT(strlen(version));

    ag_set_log_callback(on_log, (void *) (uintptr_t) 42);

    ag_dnsproxy_settings *settings = ag_dnsproxy_settings_get_default();

    ASSERT(settings->fallback_domains.size > 0);
    ASSERT(settings->fallback_domains.data);

    ASSERT(settings->upstreams.data == NULL);
    ASSERT(settings->upstreams.size == 0);

    ag_upstream_options upstream1 = {
            .address = "8.8.8.8",
            .id = 42,
    };

    ag_upstream_options upstream2 = {
            .address = "1.1.1.1",
            .id = 42,
    };

    settings->upstreams.data = &upstream1;
    settings->upstreams.size = 1;

    // Add blocking filter
    ag_filter_params filter = {
        .id = 1,
        .data = "example.org",
        .in_memory = true
    };
    settings->filter_params.filters.data = &filter;
    settings->filter_params.filters.size = 1;

    ag_dnsproxy_events events = {0};
    events.on_request_processed = on_req;
    events.on_certificate_verification = on_cert;

    ag_dnsproxy_init_result result;
    const char *message = NULL;
    ag_dnsproxy *proxy = ag_dnsproxy_init(settings, &events, &result, &message);
    ASSERT(proxy);
    ASSERT(result == AGDPIR_OK);
    ASSERT(message == NULL);

    // Initially, filter is active, so requests will be blocked
    expect_blocked_request = true;

    ag_dnsproxy_settings *actual_settings1 = ag_dnsproxy_get_settings(proxy);
    ASSERT(actual_settings1);
    ASSERT(actual_settings1->upstreams.data[0].id == settings->upstreams.data[0].id);
    ag_dnsproxy_settings_free(actual_settings1);

    // reapply settings fast
    settings->upstreams.data = &upstream2;
    settings->upstreams.size = 1;
    memset(&settings->filter_params, 0, sizeof(settings->filter_params));   // filter disable - no work

    bool reapply_result = ag_dnsproxy_reapply_settings(proxy, settings, AGDPRO_SETTINGS, &result, &message);
    ASSERT(reapply_result);
    ASSERT(result == AGDPIR_OK);
    ASSERT(message == NULL);

    ag_dnsproxy_settings *actual_settings2 = ag_dnsproxy_get_settings(proxy);
    ASSERT(actual_settings2);
    ASSERT(actual_settings2->upstreams.data[0].id == settings->upstreams.data[0].id);
    ag_dnsproxy_settings_free(actual_settings2);

    // send query
    on_req_called = false;
    ldns_pkt *query = ldns_pkt_query_new(ldns_dname_new_frm_str("example.org"),
            LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    ag_buffer msg = {0};
    size_t out_size;
    ASSERT(LDNS_STATUS_OK == ldns_pkt2wire(&msg.data, query, &out_size));
    msg.size = out_size;

    ag_buffer res = ag_dnsproxy_handle_message(proxy, msg, NULL);
    ASSERT(on_req_called);

    ldns_pkt *response = NULL;
    ASSERT(LDNS_STATUS_OK == ldns_wire2pkt(&response, res.data, res.size));
    ldns_pkt_rcode rcode = ldns_pkt_get_rcode(response);
    ASSERT(LDNS_RCODE_NOERROR == rcode);     // blocked with 0.0.0.0 answer
    uint16_t ancount = ldns_pkt_ancount(response);
    // For blocked requests with 0.0.0.0 answer, ancount should be > 0
    ASSERT(ancount > 0);

    // reapply settings full (disable filters)
    reapply_result = ag_dnsproxy_reapply_settings(proxy, settings, AGDPRO_SETTINGS | AGDPRO_FILTERS, &result, &message);
    ASSERT(reapply_result);
    ASSERT(result == AGDPIR_OK);
    ASSERT(message == NULL);

    ag_dnsproxy_settings *actual_settings3 = ag_dnsproxy_get_settings(proxy);
    ASSERT(actual_settings3);
    ASSERT(actual_settings3->upstreams.data[0].id == settings->upstreams.data[0].id);
    ag_dnsproxy_settings_free(actual_settings3);

    // send second query after full reapply (should work now - no blocking)
    ldns_pkt_free(response);
    ag_buffer_free(res);

    // Reset flags for unblocked request
    expect_blocked_request = false;
    on_req_called = false;

    res = ag_dnsproxy_handle_message(proxy, msg, NULL);
    ASSERT(on_req_called);

    ASSERT(LDNS_STATUS_OK == ldns_wire2pkt(&response, res.data, res.size));
    ASSERT(LDNS_RCODE_NOERROR == ldns_pkt_get_rcode(response));     // no error now
    ASSERT(ldns_pkt_ancount(response) > 0);

    ldns_pkt_free(response);
    ag_buffer_free(res);

    // Test filters-only reapply (reapply_upstreams=false, reapply_filters=true)
    // Re-enable blocking filter
    ag_filter_params filter2 = {
        .id = 1,
        .data = "example.org",
        .in_memory = true
    };
    settings->filter_params.filters.data = &filter2;
    settings->filter_params.filters.size = 1;

    reapply_result = ag_dnsproxy_reapply_settings(proxy, settings, AGDPRO_FILTERS, &result, &message);
    ASSERT(reapply_result);
    ASSERT(result == AGDPIR_OK);
    ASSERT(message == NULL);

    // Verify filter is now active again (request should be blocked)
    expect_blocked_request = true;
    on_req_called = false;
    res = ag_dnsproxy_handle_message(proxy, msg, NULL);
    ASSERT(on_req_called);
    ASSERT(LDNS_STATUS_OK == ldns_wire2pkt(&response, res.data, res.size));
    ASSERT(LDNS_RCODE_NOERROR == ldns_pkt_get_rcode(response));
    ASSERT(ldns_pkt_ancount(response) > 0);  // blocked with 0.0.0.0 answer

    ldns_pkt_free(response);
    ag_buffer_free(res);

    // Test no-op reapply (AGDP_RO_NONE)
    reapply_result = ag_dnsproxy_reapply_settings(proxy, settings, AGDPRO_NONE, &result, &message);
    ASSERT(reapply_result);
    ASSERT(result == AGDPIR_OK);
    ASSERT(message == NULL);

    // Verify nothing changed - filter should still be active (request should be blocked)
    on_req_called = false;
    res = ag_dnsproxy_handle_message(proxy, msg, NULL);
    ASSERT(on_req_called);
    ASSERT(LDNS_STATUS_OK == ldns_wire2pkt(&response, res.data, res.size));
    ASSERT(LDNS_RCODE_NOERROR == ldns_pkt_get_rcode(response));
    ASSERT(ldns_pkt_ancount(response) > 0);  // still blocked with 0.0.0.0 answer

    // Clear pointers before freeing to avoid double-free
    memset(&settings->upstreams, 0, sizeof(settings->upstreams));
    memset(&settings->filter_params, 0, sizeof(settings->filter_params));
    ag_dnsproxy_settings_free(settings);

    ag_dnsproxy_deinit(proxy);

    ldns_pkt_free(query);
    ldns_pkt_free(response);
    ag_buffer_free(res);
    LDNS_FREE(msg.data);
}

#define TEST_DNS_STAMP "sdns://AgcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQovZG5zLXF1ZXJ5"

static void test_dnsstamp() {
    const char *error = NULL;
    ag_dns_stamp *stamp = ag_dns_stamp_from_str("asdfasdfasdfsdf", &error);
    ASSERT(!stamp);
    ASSERT(error);

    error = NULL;
    const char *doh_str = "sdns://AgMAAAAAAAAADDk0LjE0MC4xNC4xNITK_rq-BN6tvu8PZG5zLmFkZ3VhcmQuY29tCi9kbnMtcXVlcnk";
    stamp = ag_dns_stamp_from_str(doh_str, &error);
    ASSERT(stamp);
    ASSERT(!error);
    ASSERT(0 == strcmp(stamp->provider_name, "dns.adguard.com"));
    ASSERT(0 == strcmp(stamp->path, "/dns-query"));
    ASSERT(stamp->properties);
    ASSERT(*stamp->properties & AGSIP_DNSSEC);
    ASSERT(*stamp->properties & AGSIP_NO_LOG);
    ASSERT(!(*stamp->properties & AGSIP_NO_FILTER));
    ASSERT(stamp->hashes.size == 2);
    ASSERT(0 == strcmp(ag_dns_stamp_pretty_url(stamp), "https://dns.adguard.com/dns-query"));
    ASSERT(0 == strcmp(ag_dns_stamp_prettier_url(stamp), "https://dns.adguard.com/dns-query"));
    ASSERT(0 == strcmp(ag_dns_stamp_to_str(stamp), doh_str));

    static uint8_t BYTES[] = "\xca\xfe\xba\xbe\xde\xad\xbe\xef";
    ag_buffer hash = {.data = BYTES, .size = 4};
    stamp->proto = AGSPT_DOQ;
    stamp->hashes.data = &hash;
    stamp->hashes.size = 1;
    *stamp->properties = AGSIP_NO_FILTER;
    stamp->path = NULL;

    ASSERT(0 == strcmp(ag_dns_stamp_pretty_url(stamp), "quic://dns.adguard.com"));
    ASSERT(0 == strcmp(ag_dns_stamp_prettier_url(stamp), "quic://dns.adguard.com"));
    ASSERT(0 == strcmp(ag_dns_stamp_to_str(stamp), "sdns://BAQAAAAAAAAADDk0LjE0MC4xNC4xNATK_rq-D2Rucy5hZGd1YXJkLmNvbQ"));

    stamp->proto = AGSPT_DNSCRYPT;
    stamp->hashes.size = 0;
    stamp->provider_name = "2.dnscrypt-cert.adguard";
    stamp->server_public_key.data = BYTES;
    stamp->server_public_key.size = 8;

    ASSERT(0 == strcmp(ag_dns_stamp_pretty_url(stamp), "sdns://AQQAAAAAAAAADDk0LjE0MC4xNC4xNAjK_rq-3q2-7xcyLmRuc2NyeXB0LWNlcnQuYWRndWFyZA"));
    ASSERT(0 == strcmp(ag_dns_stamp_prettier_url(stamp), "dnscrypt://2.dnscrypt-cert.adguard"));
    ASSERT(0 == strcmp(ag_dns_stamp_to_str(stamp), "sdns://AQQAAAAAAAAADDk0LjE0MC4xNC4xNAjK_rq-3q2-7xcyLmRuc2NyeXB0LWNlcnQuYWRndWFyZA"));
}

static void test_cert_fingerprint() {
    const char *version = ag_get_capi_version();
    ASSERT(version);
    ASSERT(strlen(version));

    ag_set_log_callback(on_log, (void *) (uintptr_t) 42);

    ag_dnsproxy_settings *settings = ag_dnsproxy_settings_get_default();

    ASSERT(settings->fallback_domains.size > 0);
    ASSERT(settings->fallback_domains.data);

    ASSERT(settings->upstreams.data == NULL);
    ASSERT(settings->upstreams.size == 0);

    const char *ADGUARD_DNS_SPKI = "gX+tmLZzEdlwVKPNCeIY/DGV0VIHGpdPb25KjJ4OZjU=";
    const char *bootstrap = "1.1.1.1";
    ag_upstream_options upstream = {
            .address = "tls://dns.adguard-dns.com",
            .id = 42,
    };
    upstream.bootstrap.data = &bootstrap;
    upstream.bootstrap.size = 1;
    upstream.fingerprints.data = &ADGUARD_DNS_SPKI;
    upstream.fingerprints.size = 1;

    settings->upstreams.data = &upstream;
    settings->upstreams.size = 1;

    ag_dnsproxy_events events = {0};
    events.on_request_processed = on_req;
    events.on_certificate_verification = on_cert;

    ag_dnsproxy_init_result result;
    const char *message = NULL;
    ag_dnsproxy *proxy = ag_dnsproxy_init(settings, &events, &result, &message);
    ASSERT(proxy);
    ASSERT(result == AGDPIR_OK);
    ASSERT(message == NULL);

    ag_dnsproxy_settings *actual_settings = ag_dnsproxy_get_settings(proxy);
    ASSERT(actual_settings);
    ASSERT(actual_settings->upstreams.data[0].id == settings->upstreams.data[0].id);
    ag_dnsproxy_settings_free(actual_settings);

    memset(&settings->upstreams, 0, sizeof(settings->upstreams));
    ag_dnsproxy_settings_free(settings);

    ldns_pkt *query = ldns_pkt_query_new(ldns_dname_new_frm_str("example.org"),
                                         LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    ag_buffer msg = {0};
    size_t out_size;
    ldns_pkt2wire(&msg.data, query, &out_size);
    msg.size = out_size;

    ag_buffer res = ag_dnsproxy_handle_message(proxy, msg, NULL);
    ASSERT(on_req_called);
    ASSERT(on_cert_called);

    ldns_pkt *response = NULL;
    ASSERT(LDNS_STATUS_OK == ldns_wire2pkt(&response, res.data, res.size));
    ASSERT(LDNS_RCODE_NOERROR == ldns_pkt_get_rcode(response));
    ASSERT(ldns_pkt_ancount(response) > 0);

    ag_dnsproxy_deinit(proxy);

    ldns_pkt_free(query);
    ldns_pkt_free(response);
    ag_buffer_free(res);
    LDNS_FREE(msg.data);
}

static void test_utils() {
    // test_upstream
    ag_upstream_options upstream = {0};
    upstream.address = "https://dns.google/dns-query";
    upstream.bootstrap.size = 1;
    upstream.bootstrap.data = malloc(sizeof(const char *));
    upstream.bootstrap.data[0] = "8.8.8.8";
    const char *error = ag_test_upstream(&upstream, 5000, false, on_cert, false);
    ASSERT(error == NULL);
    upstream.address = "1.2.3.4.5.6";
    error = ag_test_upstream(&upstream, 5000, false, NULL, false);
    ASSERT(error);
    upstream.address = "https://asdf.asdf.asdf/asdfdnsqueryasdf";
    error = ag_test_upstream(&upstream, 5000, false, NULL, false);
    ASSERT(error);
    ag_str_free(error);
    free(upstream.bootstrap.data);
}

static void test_filtering_log_action() {
    ag_dns_request_processed_event event = {0};
    event.domain = "example.org";
    event.type = "TEXT";
    const char *event_rule = "||example.org^$important";
    event.rules.size = 1;
    event.rules.data = &event_rule;
    ag_dns_filtering_log_action *action = ag_dns_filtering_log_action_from_event(&event);
    ASSERT(action);
    ASSERT(action->blocking == false);
    ASSERT(action->allowed_options == (AGRGO_DNSTYPE | AGRGO_IMPORTANT));
    ASSERT(action->required_options == (AGRGO_IMPORTANT));
    ASSERT(action->templates.size == 1);
    char *rule = ag_dns_generate_rule_with_options(action->templates.data[0], &event, AGRGO_IMPORTANT | AGRGO_DNSTYPE);
    ASSERT(rule);
    ASSERT(0 == strcmp("@@||example.org^$dnstype=TEXT,important", rule));
    ag_str_free(rule);
    ag_dns_filtering_log_action_free(action);
}

static void test_is_valid_rule() {
    ASSERT(ag_is_valid_dns_rule("$denyallow=com|net"));
    ASSERT(ag_is_valid_dns_rule("$denyallow=example.org"));
    ASSERT(!ag_is_valid_dns_rule("/.*/"));
}

#ifdef _WIN32
struct async_ctx_t {
    __int64 ok;
    HANDLE sem;
};

static struct async_ctx_t g_ctx;

static void async_cb(const ag_buffer *result) {
    g_ctx.ok = result->data && result->size > 0;
    ReleaseSemaphore(g_ctx.sem, 1, NULL);
}

static void test_async_transparent() {
    ag_dnsproxy_settings *settings = ag_dnsproxy_settings_get_default();
    ASSERT(settings);
    ag_upstream_options upstream = {
            .address = "1.2.3.4", // blackhole, intentional
            .id = 42,
    };
    settings->upstreams.data = &upstream;
    settings->upstreams.size = 1;
    ag_dnsproxy_init_result result;
    const char *message = NULL;
    ag_dnsproxy *proxy = ag_dnsproxy_init(settings, NULL, &result, &message);
    ASSERT(proxy);
    ldns_pkt *query = ldns_pkt_query_new(ldns_dname_new_frm_str("example.org"),
            LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    ag_buffer msg = {0};
    size_t out_size;
    ASSERT(LDNS_STATUS_OK == ldns_pkt2wire(&msg.data, query, &out_size));
    msg.size = out_size;
    ag_dns_message_info info = {.transparent = true};
    g_ctx.sem = CreateSemaphore(NULL, 0, 1, NULL);
    ag_dnsproxy_handle_message_async(proxy, msg, &info, async_cb);
    ASSERT(WAIT_OBJECT_0 == WaitForSingleObject(g_ctx.sem, 10000));
    ASSERT(g_ctx.ok);
    CloseHandle(g_ctx.sem);
    free(msg.data);
    ldns_pkt_free(query);
    ag_dnsproxy_deinit(proxy);
    settings->upstreams.data = NULL;
    settings->upstreams.size = 0;
    ag_dnsproxy_settings_free(settings);
}
#endif

int main() {
    ag_set_log_level(AGLL_TRACE);

    test_proxy();
    test_reapply_settings();
    test_utils();
    // Disabled since AG servers does not have stable SubjectPublicKeyInfo
    // test_cert_fingerprint();
    test_dnsstamp();
    test_filtering_log_action();
    test_is_valid_rule();

#ifdef _WIN32
    // At least check that we don't crash or something
    ag_disable_SetUnhandledExceptionFilter();
    ag_enable_SetUnhandledExceptionFilter();
    test_async_transparent();
#endif

    return 0;
}
