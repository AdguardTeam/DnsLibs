#include <ag_dns.h>
#include <ldns/ldns.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond) do {                                 \
    if (!(cond)) {                                        \
        fprintf(stderr,                                   \
                "\n\t%s:%d:%s() assertion (%s) failed\n", \
                __FILE__, __LINE__, __func__, #cond);     \
        exit(1);                                          \
    }                                                     \
} while (0)

static bool on_req_called = false;
static void on_req(const ag_dns_request_processed_event *event) {
    on_req_called = true;
    ASSERT(event->elapsed > 0);
    ASSERT(0 == strcmp(event->domain, "example.org."));
    ASSERT(event->answer);
    ASSERT(event->error == NULL);
    ASSERT(event->type);
    ASSERT(event->status);
    ASSERT(event->upstream_id);
    ASSERT(*event->upstream_id == 42);
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

static void on_log(void *arg, const char *name, ag_log_level level, const char *message) {
    ASSERT((uintptr_t) arg == 42);
    fprintf(stdout, "test logger: L%d [%s]: %s\n", level, name, message);
}

static void test_proxy() {
    const char *version = ag_get_capi_version();
    ASSERT(version);
    ASSERT(strlen(version));

    ag_logger_set_default_callback(on_log, (void *)(uintptr_t) 42);

    ag_dnsproxy_settings *settings = ag_dnsproxy_settings_get_default();

    const char *ugly_hack = settings->upstreams.data[0].address;
    settings->upstreams.data[0].address = "tls://1.1.1.1";
    settings->upstreams.data[0].id = 42;

    ag_dnsproxy_events events = {};
    events.on_request_processed = on_req;
    events.on_certificate_verification = on_cert;

    ag_dnsproxy *proxy = ag_dnsproxy_init(settings, &events);
    ASSERT(proxy);

    ag_dnsproxy_settings *actual_settings = ag_dnsproxy_get_settings(proxy);
    ASSERT(actual_settings);
    ASSERT(actual_settings->upstreams.data[0].id == settings->upstreams.data[0].id);
    ag_dnsproxy_settings_free(actual_settings);

    settings->upstreams.data[0].address = ugly_hack;
    ag_dnsproxy_settings_free(settings);

    ldns_pkt *query = ldns_pkt_query_new(ldns_dname_new_frm_str("example.org"),
                                         LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    ag_buffer msg = {};
    size_t out_size;
    ldns_pkt2wire(&msg.data, query, &out_size);
    msg.size = out_size;

    ag_buffer res = ag_dnsproxy_handle_message(proxy, msg);
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

#define TEST_DNS_STAMP "sdns://AgcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQovZG5zLXF1ZXJ5"

static void test_utils() {
    // DNS Stamp
    ag_parse_dns_stamp_result *result = ag_parse_dns_stamp(TEST_DNS_STAMP);
    ASSERT(NULL == result->error);
    ASSERT(0 == strcmp("127.0.0.1", result->stamp.server_addr));
    ASSERT(0 == strcmp("example.com", result->stamp.provider_name));
    ASSERT(0 == strcmp("/dns-query", result->stamp.path));
    ASSERT(AGSPT_DOH == result->stamp.proto);
    ASSERT(0 == result->stamp.server_public_key.size);
    ASSERT(1 == result->stamp.hashes.size);
    ASSERT((int)result->stamp.properties == (AGSIP_DNSSEC | AGSIP_NO_LOG | AGSIP_NO_FILTER));
    ag_parse_dns_stamp_result_free(result);

    result = ag_parse_dns_stamp("sdns://abcdefgh");
    ASSERT(NULL != result->error);
    ag_parse_dns_stamp_result_free(result);


    // test_upstream
    ag_upstream_options upstream = {};
    upstream.address = "https://dns.adguard.com/dns-query";
    upstream.bootstrap.size = 1;
    upstream.bootstrap.data = malloc(sizeof(const char *));
    upstream.bootstrap.data[0] = "8.8.8.8";
    upstream.timeout_ms = 5000;
    const char *error = ag_test_upstream(&upstream, on_cert);
    ASSERT(error == NULL);
    upstream.address = "1.2.3.4.5.6";
    error = ag_test_upstream(&upstream, NULL);
    ASSERT(error);
    upstream.address = "https://asdf.asdf.asdf/asdfdnsqueryasdf";
    error = ag_test_upstream(&upstream, NULL);
    ASSERT(error);
    ag_str_free(error);
    free(upstream.bootstrap.data);
}

int main() {
    ag_set_default_log_level(AGLL_TRACE);

    test_proxy();
    test_utils();

#ifdef _WIN32
    // At least check that we don't crash or something
    ag_disable_SetUnhandledExceptionFilter();
    ag_enable_SetUnhandledExceptionFilter();
#endif

    return 0;
}
