package com.adguard.dnslibs.proxy;

import android.Manifest;
import android.content.Context;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.espresso.core.internal.deps.guava.collect.Lists;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.rule.GrantPermissionRule;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Instrumented test, which will execute on an Android device.
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class DnsProxyTest {
    static {
        DnsProxy.setLogLevel(DnsProxy.LogLevel.TRACE);
    }

    private static final Logger log = LoggerFactory.getLogger(DnsProxyTest.class);
    private final Context context = ApplicationProvider.getApplicationContext();

    // Proxy won't initialize without upstreams, and since recently
    // there are no upstreams in default settings.
    private static DnsProxySettings getDefaultSettings() {
        DnsProxySettings settings = DnsProxySettings.getDefault();
        UpstreamSettings google = new UpstreamSettings();
        google.setAddress("8.8.8.8");
        settings.getUpstreams().add(google);
        return settings;
    }

    // In case of "permission denied", try uninstalling the test application from the device.
    @Rule
    public GrantPermissionRule rule = GrantPermissionRule.grant(
            Manifest.permission.INTERNET,
            Manifest.permission.ACCESS_NETWORK_STATE,
            Manifest.permission.ACCESS_WIFI_STATE
    );

    @Test
    public void testProxyInit() {
        final DnsProxySettings defaultSettings = getDefaultSettings();
        try (final DnsProxy proxy = new DnsProxy(context, defaultSettings)) {
            assertEquals(proxy.getSettings(), defaultSettings);
        }

        final DnsProxy proxy = new DnsProxy(context, defaultSettings);
        proxy.close();
        proxy.close();
        proxy.close();
        proxy.close(); // Check that multiple close() doesn't crash
    }

    @Test
    public void testHandleMessage() {
        try (final DnsProxy proxy = new DnsProxy(context, getDefaultSettings())) {
            final byte[] request = new byte[64];
            ThreadLocalRandom.current().nextBytes(request);

            byte[] response = proxy.handleMessage(request);
            assertNotNull(response);
            assertEquals(12, response.length);
            assertEquals(request[0], response[0]);
            assertEquals(request[1], response[1]);
            assertEquals(1, response[3] & 0xf); // FORMERR

            response = proxy.handleMessage(new byte[0]);
            assertNotNull(response);
            assertEquals(0, response.length);
        }
    }

    @Test
    public void testEventsMultithreaded() {
        final DnsProxySettings settings = getDefaultSettings();
        settings.getUpstreams().clear();
        settings.getUpstreams().add(new UpstreamSettings(
                "1.1.1.1", Collections.emptyList(), new byte[]{}, 42));
        settings.setUpstreamTimeoutMs(10000);

        final List<DnsRequestProcessedEvent> eventList =
                Collections.synchronizedList(new ArrayList<DnsRequestProcessedEvent>());

        final DnsProxyEvents events = new DnsProxyEvents() {
            @Override
            public void onRequestProcessed(DnsRequestProcessedEvent event) {
                log.info("DNS request processed event: {}", event.toString());
                eventList.add(event);
            }
        };

        try (final DnsProxy proxy = new DnsProxy(context, settings, events)) {
            final List<Thread> threads = new ArrayList<>();
            for (int i = 0; i < 10; ++i) {
                final Thread t = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            final Message req = Message.newQuery(Record.newRecord(Name.fromString("google.com."), Type.A, DClass.IN));
                            final Message res = new Message(proxy.handleMessage(req.toWire()));
                            assertEquals(Rcode.NOERROR, res.getRcode());
                        } catch (IOException e) {
                            throw new UncheckedIOException(e);
                        }
                    }
                });
                t.start();
                threads.add(t);
            }

            for (final Thread t : threads) {
                try {
                    t.join();
                } catch (InterruptedException ignored) {
                }
            }

            assertEquals(threads.size(), eventList.size());
            for (final DnsRequestProcessedEvent event : eventList) {
                assertNotNull(event.getError());
                assertTrue(event.getError().isEmpty());
                assertNotNull(event.getAnswer());
                assertNotNull(event.getDomain());
                assertEquals("google.com.", event.getDomain());
                assertNotNull(event.getUpstreamId());
                assertEquals(42, (int) event.getUpstreamId());
                assertNotNull(event.getFilterListIds());
                assertNotNull(event.getRules());
                assertNotNull(event.getType());
            }
        }
    }

    @Test
    public void testListeners() {
        final DnsProxySettings settings = getDefaultSettings();
        final ListenerSettings tcp = new ListenerSettings();
        tcp.setAddress("::");
        tcp.setPort(12345);
        tcp.setProtocol(ListenerSettings.Protocol.TCP);
        tcp.setPersistent(true);
        tcp.setIdleTimeoutMs(5000);
        settings.getListeners().add(tcp);

        final ListenerSettings udp = new ListenerSettings();
        udp.setAddress("::");
        udp.setPort(12345);
        udp.setProtocol(ListenerSettings.Protocol.UDP);
        settings.getListeners().add(udp);

        try (final DnsProxy proxy = new DnsProxy(context, settings)) {
            assertEquals(proxy.getSettings(), settings);
        }
    }

    @Test
    public void testSettingsMarshalling() {
        final DnsProxySettings settings = getDefaultSettings();

        settings.setBlockedResponseTtlSecs(1234);

        settings.setIpv6Available(ThreadLocalRandom.current().nextBoolean());
        settings.setBlockIpv6(ThreadLocalRandom.current().nextBoolean());

// FIXME can't do these anymore: wrong filter path == proxy won't initialize
//        settings.getFilterParams().put(1, "/Й/И/Л"); // Test CESU-8 encoding
//        settings.getFilterParams().put(-2, "/A/B/C/D/Ы/Щ");
//        settings.getFilterParams().put(Integer.MAX_VALUE, "/A/B/Я/З/Ъ");
//        settings.getFilterParams().put(Integer.MIN_VALUE, "a/b\u0000c/d");

        settings.getFilterParams().add(new FilterParams(42, "0.0.0.0 doubleclick.net", true));

        final ListenerSettings tcp = new ListenerSettings();
        tcp.setAddress("::");
        tcp.setPort(12345);
        tcp.setProtocol(ListenerSettings.Protocol.TCP);
        tcp.setPersistent(true);
        tcp.setIdleTimeoutMs(5000);
        settings.getListeners().add(tcp);

        final ListenerSettings udp = new ListenerSettings();
        udp.setAddress("::");
        udp.setPort(12345);
        udp.setProtocol(ListenerSettings.Protocol.UDP);
        settings.getListeners().add(udp);

        final UpstreamSettings dot = new UpstreamSettings();
        dot.setAddress("tls://dns.adguard.com");
        dot.getBootstrap().add("8.8.8.8");
        dot.setServerIp(new byte[]{8, 8, 8, 8});
        dot.setId(42);
        dot.setOutboundInterfaceName("whtvr0");
        settings.getUpstreams().add(dot);

        settings.getUpstreams().get(0).setOutboundInterfaceName("");

        final Dns64Settings dns64 = new Dns64Settings();
        dns64.setUpstreams(Collections.singletonList(dot));
        dns64.setMaxTries(1234);
        dns64.setWaitTimeMs(3456);
        settings.setDns64(dns64);

        settings.setListeners(settings.getListeners());
        settings.setUpstreams(settings.getUpstreams());
        settings.setFilterParams(settings.getFilterParams());
        settings.getUpstreams().get(0).setBootstrap(Collections.singletonList("1.1.1.1"));

        settings.setAdblockRulesBlockingMode(DnsProxySettings.BlockingMode.REFUSED);
        settings.setHostsRulesBlockingMode(DnsProxySettings.BlockingMode.ADDRESS);
        settings.setCustomBlockingIpv4("4.3.2.1");
        settings.setCustomBlockingIpv6("43::21");

        settings.setDnsCacheSize(42);
        settings.setOptimisticCache(true);
        settings.enableDNSSECOK(true);
        settings.setOptimisticCache(true);
        settings.setEnableRetransmissionHandling(true);

        UpstreamSettings fallbackUpstream = new UpstreamSettings();
        fallbackUpstream.setAddress("https://fall.back/up/stream");
        fallbackUpstream.setBootstrap(Collections.singletonList("1.1.1.1"));
        fallbackUpstream.setServerIp(new byte[]{8, 8, 8, 8});
        settings.getFallbacks().add(fallbackUpstream);

        settings.setUpstreamTimeoutMs(4200);

        settings.setOutboundProxy(
                new OutboundProxySettings(OutboundProxySettings.Protocol.SOCKS5_UDP, "::", 1234,
                        null, new OutboundProxySettings.AuthInfo("1", "2"), true, false));

        settings.setEnableParallelUpstreamQueries(true);
        settings.setEnableFallbackOnUpstreamsFailure(true);
        settings.setEnableServfailOnUpstreamsFailure(true);

        try (final DnsProxy proxy = new DnsProxy(context, settings)) {
            assertEquals(settings, proxy.getSettings());
            assertFalse(proxy.getSettings().getListeners().isEmpty());
            assertFalse(proxy.getSettings().getUpstreams().isEmpty());
            assertFalse(proxy.getSettings().getUpstreams().get(0).getBootstrap().isEmpty());
        }

        settings.setCustomBlockingIpv4(null);
        settings.setCustomBlockingIpv6(null);

        settings.setFallbackDomains(Arrays.asList("abcd", "*asdf.*.com", "*.localdomain"));

        // Important: this field does not survive the round-trip between java and native,
        // since it doesn't exist in the native settings struct. Set to false to win.
        settings.setDetectSearchDomains(false);

        try (final DnsProxy proxy = new DnsProxy(context, settings)) {
            assertTrue(proxy.getSettings().getCustomBlockingIpv4().isEmpty());
            assertTrue(proxy.getSettings().getCustomBlockingIpv6().isEmpty());
            settings.setCustomBlockingIpv4("");
            settings.setCustomBlockingIpv6("");
            assertEquals(settings, proxy.getSettings());
        }
    }

    private void testCertificateVerification(String upstreamAddr) {
        final UpstreamSettings us = new UpstreamSettings();
        us.setAddress(upstreamAddr);
        us.getBootstrap().add("8.8.8.8");
        final DnsProxySettings settings = getDefaultSettings();
        settings.getUpstreams().clear();
        settings.getUpstreams().add(us);
        settings.setUpstreamTimeoutMs(10000);
        settings.setIpv6Available(false); // DoT times out trying to reach dns.adguard.com over IPv6

        final DnsProxyEvents events = new DnsProxyEvents() {
            @Override
            public void onRequestProcessed(DnsRequestProcessedEvent event) {
                log.info("DNS request processed event: {}", event.toString());
            }
        };

        try (final DnsProxy proxy = new DnsProxy(context, settings, events)) {
            assertEquals(settings, proxy.getSettings());

            final Message req = Message.newQuery(Record.newRecord(Name.fromString("google.com."), Type.A, DClass.IN));
            final Message res = new Message(proxy.handleMessage(req.toWire()));

            assertEquals(Rcode.NOERROR, res.getRcode());
        } catch (IOException e) {
            fail(e.toString());
        }
    }

    @Test
    public void testDoT() {
        testCertificateVerification("tls://dns.adguard-dns.com");
        testCertificateVerification("tls://1.1.1.1");
        testCertificateVerification("tls://one.one.one.one");
    }

    @Test
    public void testDoH() {
        testCertificateVerification("https://dns.google/dns-query");
        testCertificateVerification("https://dns.cloudflare.com/dns-query");
    }

    @Test
    public void testCheckRule() {
        assertFalse(DnsProxy.isValidRule("||||example"));
        assertTrue(DnsProxy.isValidRule("||example"));
    }

    private void testCertificateVerificationWithFingerprint(String upstreamAddr, String certFingerprint, boolean isSuccessExpected) {
        final UpstreamSettings us = new UpstreamSettings();
        us.setAddress(upstreamAddr);
        us.getBootstrap().add("8.8.8.8");
        us.getFingerprints().add(certFingerprint);
        final DnsProxySettings settings = getDefaultSettings();
        settings.getUpstreams().clear();
        settings.getUpstreams().add(us);
        settings.setUpstreamTimeoutMs(10000);
        settings.setIpv6Available(false); // DoT times out trying to reach dns.adguard.com over IPv6

        final DnsProxyEvents events = new DnsProxyEvents() {
            @Override
            public void onRequestProcessed(DnsRequestProcessedEvent event) {
                log.info("DNS request processed event: {}", event.toString());
            }
        };

        try (final DnsProxy proxy = new DnsProxy(context, settings, events)) {
            assertEquals(settings, proxy.getSettings());

            final Message req = Message.newQuery(Record.newRecord(Name.fromString("google.com."), Type.A, DClass.IN));
            final Message res = new Message(proxy.handleMessage(req.toWire()));

            if (isSuccessExpected) {
                assertEquals(Rcode.NOERROR, res.getRcode());
            } else {
                assertEquals(Rcode.SERVFAIL, res.getRcode());
            }
        } catch (IOException e) {
            fail(e.toString());
        }
    }

    @Test
    public void testFingerprint() {
        String f = "Eg+H87YhlVD9X1phBlRsmfDwqWnPcccfgIQKVfaEPyY=";
        testCertificateVerificationWithFingerprint("tls://dns.adguard-dns.com", f, true);
        f = "R3hcMOAGw0WFztuG2skTodoHp8IGid3Qg63Cn7YUYoM=";
        testCertificateVerificationWithFingerprint("tls://dns.adguard-dns.com", f, true);
    }

    @Test
    public void testWrongFingerprint() {
        String f = "SOMEWRONGFINGERPRINT";
        testCertificateVerificationWithFingerprint("tls://dns.adguard-dns.com", f, false);
    }

    private static byte[] toByteArray(String str) {
        byte [] key = new BigInteger(str, 16).toByteArray();
        while (key.length > 0 && key[0] == 0) {
            key = Arrays.copyOfRange(key, 1, key.length);
        }
        return key;
    }

    static class TestParam {
        public final String stampStr;
        public final DnsStamp dnsStamp;
        public final String prettyUrl;
        public final String prettierUrl;

        TestParam(String stampStr, DnsStamp dnsStamp, String prettyUrl, String prettierUrl) {
            this.stampStr = stampStr;
            this.dnsStamp = dnsStamp;
            this.prettyUrl = prettyUrl;
            this.prettierUrl = prettierUrl;
        }
    }

    @Test
    public void testParseDNSStamp() {

        List<TestParam> testParams = new ArrayList<TestParam>() {
            void put(String stampStr, DnsStamp dnsStamp, String prettyUrl, String prettierUrl) {
                add(new TestParam(stampStr, dnsStamp, prettyUrl, prettierUrl));
            }
            {
            // Plain
            put("sdns://AAcAAAAAAAAABzguOC44Ljg",
                new DnsStamp(DnsStamp.ProtoType.PLAIN, "8.8.8.8", "", "", null,
                        EnumSet.of(DnsStamp.InformalProperties.DNSSEC, DnsStamp.InformalProperties.NO_LOG, DnsStamp.InformalProperties.NO_FILTER),
                        null), "8.8.8.8", "8.8.8.8");
            // AdGuard DNS (DNSCrypt)
            put("sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
                new DnsStamp(DnsStamp.ProtoType.DNSCRYPT, "176.103.130.130:5443", "2.dnscrypt.default.ns1.adguard.com", "",
                        toByteArray("d12b47f252dcf2c2bbf8991086eaf79ce4495d8b16c8a0c4322e52ca3f390873"),
                        EnumSet.of(DnsStamp.InformalProperties.NO_LOG),
                        null),
                         "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
                         "dnscrypt://2.dnscrypt.default.ns1.adguard.com");
            // DoH
            put("sdns://AgcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQovZG5zLXF1ZXJ5",
                new DnsStamp(DnsStamp.ProtoType.DOH, "127.0.0.1", "example.com", "/dns-query",
                        null,
                        EnumSet.of(DnsStamp.InformalProperties.DNSSEC, DnsStamp.InformalProperties.NO_LOG, DnsStamp.InformalProperties.NO_FILTER),
                        Lists.newArrayList(toByteArray("c3846bf24b9e93ca64274c0ec67c1ecc5e024ffcacd2d74019350e81fe546ae4"))),
                        "https://example.com/dns-query", "https://example.com/dns-query");
            // DoT
            put("sdns://AwcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQ",
                new DnsStamp(DnsStamp.ProtoType.TLS, "127.0.0.1", "example.com", "",
                        null,
                        EnumSet.of(DnsStamp.InformalProperties.DNSSEC, DnsStamp.InformalProperties.NO_LOG, DnsStamp.InformalProperties.NO_FILTER),
                        Lists.newArrayList(toByteArray("c3846bf24b9e93ca64274c0ec67c1ecc5e024ffcacd2d74019350e81fe546ae4"))),
                        "tls://example.com", "tls://example.com");
            // Plain (IPv6)
            put("sdns://AAcAAAAAAAAAGltmZTgwOjo2ZDZkOmY3MmM6M2FkOjYwYjhd",
                new DnsStamp(DnsStamp.ProtoType.PLAIN, "[fe80::6d6d:f72c:3ad:60b8]", "", "", null,
                        EnumSet.of(DnsStamp.InformalProperties.DNSSEC, DnsStamp.InformalProperties.NO_LOG, DnsStamp.InformalProperties.NO_FILTER),
                        null), "fe80::6d6d:f72c:3ad:60b8", "fe80::6d6d:f72c:3ad:60b8");
        }};

        for (TestParam param : testParams) {
            try {
                DnsStamp dnsStamp = DnsStamp.parse(param.stampStr);
                assertEquals(dnsStamp, param.dnsStamp);
                assertEquals(dnsStamp.toString(), param.stampStr);
                assertEquals(dnsStamp.getPrettyUrl(), param.prettyUrl);
                assertEquals(dnsStamp.getPrettierUrl(), param.prettierUrl);
            } catch (Exception e) {
                fail(e.toString());
            }
        }
        try {
            DnsStamp dnsStamp = DnsStamp.parse("");
        } catch (Exception e) {
            assertFalse(e.toString().isEmpty());
        }
    }

    @Test
    public void testTestUpstream() {
        final int timeout = 500; // ms
        IllegalArgumentException e0 = null;
        try {
            DnsProxy.testUpstream(new UpstreamSettings("123.12.32.1:1493", new ArrayList<String>(), null, 42),
                    timeout, false, false);
        } catch (IllegalArgumentException e) {
            e0 = e;
        }
        assertNotNull(e0);
        try {
            DnsProxy.testUpstream(new UpstreamSettings("8.8.8.8:53", new ArrayList<String>(), null, 42),
                    10 * timeout, false, false);
        } catch (IllegalArgumentException e) {
            fail(e.toString());
        }
        try {
            ArrayList<String> bootstrap = new ArrayList<>();
            bootstrap.add("1.2.3.4");
            bootstrap.add("8.8.8.8");
            DnsProxy.testUpstream(new UpstreamSettings("tls://dns.adguard-dns.com", bootstrap, null, 42),
                    10 * timeout, false, false);
        } catch (IllegalArgumentException e) {
            fail(e.toString());
        }
    }

    @Test
    public void testBlockingModeCode() {
        for (final DnsProxySettings.BlockingMode bm : DnsProxySettings.BlockingMode.values()) {
            final DnsProxySettings.BlockingMode bmFromCode = DnsProxySettings.BlockingMode.fromCode(bm.getCode());
            assertEquals(bm, bmFromCode);
        }
    }

    @Test
    public void testFilteringLogAction() {
        try (DnsProxy proxy = new DnsProxy(context, getDefaultSettings())) {
            DnsRequestProcessedEvent event = new DnsRequestProcessedEvent();
            event.setDomain("example.org");
            event.setType("TEXT");
            event.setRules(Arrays.asList("||example.org^$important"));
            FilteringLogAction action = proxy.filteringLogActionFromEvent(event);
            assertNotNull(action);
            assertNotNull(action.getTemplates());
            assertEquals(1, action.getTemplates().size());
            assertEquals(EnumSet.of(FilteringLogAction.Option.IMPORTANT), action.getRequiredOptions());
            assertEquals(EnumSet.of(FilteringLogAction.Option.IMPORTANT, FilteringLogAction.Option.DNSTYPE),
                    action.getAllowedOptions());
            assertFalse(action.isBlocking());
            assertEquals("@@||example.org^$dnstype=TEXT,important",
                    proxy.generateRuleWithOptions(action.getTemplates().get(0),
                            event, EnumSet.of(FilteringLogAction.Option.DNSTYPE,
                                    FilteringLogAction.Option.IMPORTANT)));
        }
    }
}
