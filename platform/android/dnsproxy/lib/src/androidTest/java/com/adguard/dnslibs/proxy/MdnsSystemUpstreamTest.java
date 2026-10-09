package com.adguard.dnslibs.proxy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.Manifest;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.rule.GrantPermissionRule;

import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * Device test for the Android mDNS integration of the {@code system://} upstream.
 *
 * <p>Resolving a {@code .local} name goes through the built-in mDNS client and must hold a
 * {@code WifiManager.MulticastLock} while the multicast listener sockets are open. The sockets
 * stay off the VPN through the socket factory's protect callback; an explicit network binding
 * is only applied for {@code system://<interface>} when
 * {@code USE_INTERFACE_NAMES_IN_SYSTEM_UPSTREAM} is enabled.
 */
@RunWith(AndroidJUnit4.class)
public class MdnsSystemUpstreamTest {
    private static final long WAIT_TIMEOUT_MS = 15_000;

    private final Context context = ApplicationProvider.getApplicationContext();

    @Rule
    public GrantPermissionRule rule = GrantPermissionRule.grant(
            Manifest.permission.INTERNET,
            Manifest.permission.ACCESS_NETWORK_STATE,
            Manifest.permission.ACCESS_WIFI_STATE
    );

    @Test
    public void mdnsAcquiresMulticastLock() throws IOException, InterruptedException {
        final DnsProxySettings settings = makeSystemUpstreamSettings("system://");
        try (DnsProxy proxy = new DnsProxy(context, settings)) {
            // A `.local` question is routed to the built-in mDNS client by the system:// upstream.
            final Message request = Message.newQuery(
                    Record.newRecord(Name.fromString("dns-libs-mdns-test.local."), Type.A, DClass.IN));
            final byte[] responseBytes = proxy.handleMessage(request.toWire(), null);
            assertNotNull("mDNS query must produce a response", responseBytes);

            // While the mDNS listener sockets are open, the MulticastLock must be held...
            assertTrue("WifiManager.MulticastLock must be held while mDNS listeners are open",
                    MdnsTestHooks.isMulticastLockHeld());

            // ...and released again after the mDNS idle timeout.
            final long deadline = System.currentTimeMillis() + WAIT_TIMEOUT_MS;
            while (MdnsTestHooks.isMulticastLockHeld() && System.currentTimeMillis() < deadline) {
                TimeUnit.MILLISECONDS.sleep(100);
            }
            assertFalse("WifiManager.MulticastLock must be released after the mDNS idle timeout",
                    MdnsTestHooks.isMulticastLockHeld());
        }
    }

    /**
     * Real-LAN integration test: resolves a host that advertises itself over mDNS (e.g. a
     * Steam Deck as {@code steamdeck.local}) through the {@code system://} upstream and
     * verifies the answer and the multicast lock.
     *
     * <p>Pass the host with {@code -e mdnsHost=<name>} (and optionally the expected address
     * with {@code -e mdnsHostAddress=<ip>}). Without {@code mdnsHost} the test is skipped.
     */
    @Test
    public void resolvesRealMdnsHost() throws IOException {
        final String host = InstrumentationRegistry.getArguments().getString("mdnsHost");
        Assume.assumeTrue("Pass -e mdnsHost=<name> to run the real-LAN mDNS test",
                host != null && !host.trim().isEmpty());
        final String expectedAddress = InstrumentationRegistry.getArguments().getString("mdnsHostAddress");

        final DnsProxySettings settings = makeSystemUpstreamSettings("system://");
        try (DnsProxy proxy = new DnsProxy(context, settings)) {
            final Name name = Name.fromString(host.endsWith(".") ? host : host + ".");
            final Message request = Message.newQuery(Record.newRecord(name, Type.A, DClass.IN));
            final Message response = new Message(proxy.handleMessage(request.toWire(), null));

            assertEquals("Expected " + name + " to resolve over mDNS", Rcode.NOERROR, response.getRcode());

            boolean hasAddress = false;
            for (Record rr : response.getSectionArray(Section.ANSWER)) {
                if (rr.getType() != Type.A) {
                    continue;
                }
                hasAddress = true;
                if (expectedAddress != null && !expectedAddress.isEmpty()) {
                    assertEquals("Resolved address mismatch", expectedAddress, rr.rdataToString());
                }
            }
            assertTrue("Expected an A answer for " + name, hasAddress);

            assertTrue("MulticastLock must be held while mDNS listeners are open",
                    MdnsTestHooks.isMulticastLockHeld());
        }
    }

    /**
     * With {@code USE_INTERFACE_NAMES_IN_SYSTEM_UPSTREAM} enabled, {@code system://<interface>}
     * binds the mDNS sockets to that interface's network handle. The default AAR build has the
     * option off (and {@code system://<interface>} fails to initialize there), so this is
     * skipped in that case.
     */
    @Test
    public void bindsSocketsForSystemUpstreamWithInterface() throws IOException {
        Assume.assumeTrue("USE_INTERFACE_NAMES_IN_SYSTEM_UPSTREAM is OFF",
                com.adguard.dnslibs.BuildConfig.USE_INTERFACE_NAMES_IN_SYSTEM_UPSTREAM);

        final ConnectivityManager connectivityManager =
                (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        Network wifi = null;
        String wifiInterface = null;
        if (connectivityManager != null) {
            for (Network network : connectivityManager.getAllNetworks()) {
                final NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(network);
                if (capabilities == null || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                        || !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                    continue;
                }
                final LinkProperties linkProperties = connectivityManager.getLinkProperties(network);
                if (linkProperties != null && linkProperties.getInterfaceName() != null) {
                    wifi = network;
                    wifiInterface = linkProperties.getInterfaceName();
                    break;
                }
            }
        }
        Assume.assumeTrue("No Wi-Fi network with an interface name on this device", wifi != null);

        final DnsProxySettings settings = makeSystemUpstreamSettings("system://" + wifiInterface);
        try (DnsProxy proxy = new DnsProxy(context, settings)) {
            final Message request = Message.newQuery(
                    Record.newRecord(Name.fromString("dns-libs-mdns-test.local."), Type.A, DClass.IN));
            assertNotNull(proxy.handleMessage(request.toWire(), null));

            assertEquals("mDNS sockets must be bound to the interface network handle",
                    wifi.getNetworkHandle(), MdnsTestHooks.getLastBoundNetworkHandle());
        }
    }

    private DnsProxySettings makeSystemUpstreamSettings(String upstreamAddress) {
        final DnsProxySettings settings = DnsProxySettings.getDefault();
        settings.getUpstreams().clear();
        final UpstreamSettings systemUpstream = new UpstreamSettings();
        systemUpstream.setAddress(upstreamAddress);
        systemUpstream.setId(100);
        settings.getUpstreams().add(systemUpstream);
        settings.setUpstreamTimeoutMs(5000);
        return settings;
    }
}
