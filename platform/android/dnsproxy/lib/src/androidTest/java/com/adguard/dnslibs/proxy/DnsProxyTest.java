package com.adguard.dnslibs.proxy;

import android.Manifest;

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
import java.util.ArrayList;
import java.util.Collections;
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

    // In case of "permission denied", try uninstalling the test application from the device.
    @Rule
    public GrantPermissionRule rule = GrantPermissionRule.grant(
            Manifest.permission.INTERNET,
            Manifest.permission.ACCESS_NETWORK_STATE,
            Manifest.permission.ACCESS_WIFI_STATE
    );

    @Test
    public void testProxyInit() {
        final DnsProxySettings defaultSettings = DnsProxySettings.getDefault();
        try (final DnsProxy proxy = new DnsProxy(defaultSettings)) {
            assertEquals(proxy.getSettings(), defaultSettings);
        }

        final DnsProxy proxy = new DnsProxy(defaultSettings);
        proxy.close();
        proxy.close();
        proxy.close();
        proxy.close(); // Check that multiple close() doesn't crash
    }

    @Test
    public void testHandleMessage() {
        try (final DnsProxy proxy = new DnsProxy(DnsProxySettings.getDefault())) {
            final byte[] request = new byte[64];
            ThreadLocalRandom.current().nextBytes(request);
            final byte[] response = proxy.handleMessage(request); // returns empty array on error
            assertNotNull(response);
            assertEquals(0, response.length);
        }
    }

    @Test
    public void testEventsMultithreaded() {
        final DnsProxySettings settings = DnsProxySettings.getDefault();
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

        final List<DnsRequestProcessedEvent> eventList =
                Collections.synchronizedList(new ArrayList<DnsRequestProcessedEvent>());

        final DnsProxyEvents events = new DnsProxyEvents() {
            @Override
            public void onRequestProcessed(DnsRequestProcessedEvent event) {
                log.info("DNS request processed event: {}", event.toString());
                eventList.add(event);
            }
        };

        try (final DnsProxy proxy = new DnsProxy(settings, events)) {
            final List<Thread> threads = new ArrayList<>();
            for (int i = 0; i < 10; ++i) {
                final Thread t = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        final byte[] request = new byte[64];
                        ThreadLocalRandom.current().nextBytes(request);

                        final byte[] response = proxy.handleMessage(request);
                        assertNotNull(response);
                        assertEquals(0, response.length);
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
                assertNotNull(event.getAnswer());
                assertNotNull(event.getDomain());
                assertNotNull(event.getUpstreamAddr());
                assertNotNull(event.getFilterListIds());
                assertNotNull(event.getRules());
                assertNotNull(event.getType());
                assertFalse(event.getError().isEmpty()); // 64 random bytes should result in parsing error...
            }
        }
    }

    @Test
    public void testListeners() {
        final DnsProxySettings settings = DnsProxySettings.getDefault();
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

        try (final DnsProxy proxy = new DnsProxy(settings)) {
            assertEquals(proxy.getSettings(), settings);
        }
    }

    @Test
    public void testSettingsMarshalling() {
        final DnsProxySettings settings = DnsProxySettings.getDefault();

        settings.setBlockedResponseTtlSecs(1234);

        settings.setIpv6Available(ThreadLocalRandom.current().nextBoolean());
        settings.setBlockIpv6(ThreadLocalRandom.current().nextBoolean());

        settings.getFilterParams().put(1, "/Й/И/Л"); // Test CESU-8 encoding
        settings.getFilterParams().put(2, "/A/B/C/D/Ы/Щ");
        settings.getFilterParams().put(3, "/A/B/Я/З/Ъ");
        settings.getFilterParams().put(4, "a/b\u0000c/d");

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
        dot.setTimeoutMs(10000);
        settings.getUpstreams().add(dot);

        final Dns64Settings dns64 = new Dns64Settings();
        dns64.setUpstreams(Collections.singletonList(dot));
        dns64.setMaxTries(1234);
        dns64.setWaitTimeMs(3456);
        settings.setDns64(dns64);

        settings.setListeners(settings.getListeners());
        settings.setUpstreams(settings.getUpstreams());
        settings.setFilterParams(settings.getFilterParams());
        settings.getUpstreams().get(0).setBootstrap(Collections.singletonList("1.1.1.1"));

        try (final DnsProxy proxy = new DnsProxy(settings)) {
            assertEquals(settings, proxy.getSettings());
            assertFalse(proxy.getSettings().getListeners().isEmpty());
            assertFalse(proxy.getSettings().getUpstreams().isEmpty());
            assertFalse(proxy.getSettings().getUpstreams().get(0).getBootstrap().isEmpty());
        }
    }

    private void testCertificateVerification(String upstreamAddr) {
        final UpstreamSettings us = new UpstreamSettings();
        us.setAddress(upstreamAddr);
        us.getBootstrap().add("8.8.8.8");
        us.setTimeoutMs(10000);
        final DnsProxySettings settings = DnsProxySettings.getDefault();
        settings.getUpstreams().clear();
        settings.getUpstreams().add(us);
        settings.setIpv6Available(false); // DoT times out trying to reach dns.adguard.com over IPv6

        final DnsProxyEvents events = new DnsProxyEvents() {
            @Override
            public void onRequestProcessed(DnsRequestProcessedEvent event) {
                log.info("DNS request processed event: {}", event.toString());
            }
        };

        try (final DnsProxy proxy = new DnsProxy(settings, events)) {
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
        testCertificateVerification("tls://dns.adguard.com");
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
}
