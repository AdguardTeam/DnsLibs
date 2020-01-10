package com.adguard.dnslibs.proxy;

import android.util.LongSparseArray;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class DnsProxySettings {
    private List<UpstreamSettings> upstreams = new ArrayList<>();
    private Dns64Settings dns64;
    private long blockedResponseTtlSecs;
    private LongSparseArray<String> filterParams = new LongSparseArray<>();
    private List<ListenerSettings> listeners = new ArrayList<>();
    private boolean ipv6Available;
    private boolean blockIpv6;

    /**
     * @return DNS upstreams settings list.
     */
    List<UpstreamSettings> getUpstreams() {
        return upstreams;
    }

    /**
     * @param upstreams DNS upstreams settings list.
     */
    public void setUpstreams(List<UpstreamSettings> upstreams) {
        this.upstreams = new ArrayList<>(upstreams);
    }

    /**
     * @return DNS64 settings. If {@code null}, DNS64 is disabled.
     */
    public Dns64Settings getDns64() {
        return dns64;
    }

    /**
     * @param dns64 DNS64 settings. If {@code null}, DNS64 is disabled.
     */
    public void setDns64(Dns64Settings dns64) {
        this.dns64 = dns64;
    }

    /**
     * @return TTL of the record for the blocked domains (in seconds).
     */
    public long getBlockedResponseTtlSecs() {
        return blockedResponseTtlSecs;
    }

    /**
     * @param blockedResponseTtlSecs TTL of the record for the blocked domains (in seconds).
     */
    public void setBlockedResponseTtlSecs(long blockedResponseTtlSecs) {
        this.blockedResponseTtlSecs = blockedResponseTtlSecs;
    }

    /**
     * @return Filter engine parameters. Filter files with identifiers.
     */
    LongSparseArray<String> getFilterParams() {
        return filterParams;
    }

    /**
     * @param filterParams Filter engine parameters. Filter files with identifiers.
     */
    public void setFilterParams(LongSparseArray<String> filterParams) {
        this.filterParams = new LongSparseArray<>(filterParams.size());
        for (int i = 0; i < filterParams.size(); ++i) {
            getFilterParams().put(filterParams.keyAt(i), filterParams.valueAt(i));
        }
    }

    /**
     * @param filterParams Filter engine parameters. Filter files with identifiers.
     */
    public void setFilterParams(Map<Long, String> filterParams) {
        this.filterParams = new LongSparseArray<>(filterParams.size());
        for (final Map.Entry<Long, String> e : filterParams.entrySet()) {
            getFilterParams().put(e.getKey(), e.getValue());
        }
    }

    /**
     * @return List of addresses/ports/protocols/etc... to listen on.
     */
    List<ListenerSettings> getListeners() {
        return listeners;
    }

    /**
     * @param listeners List of addresses/ports/protocols/etc... to listen on.
     */
    public void setListeners(List<ListenerSettings> listeners) {
        this.listeners = new ArrayList<>(listeners);
    }

    /**
     * @return whether bootstrappers will fetch AAAA records.
     */
    public boolean isIpv6Available() {
        return ipv6Available;
    }

    /**
     * @param ipv6Available if {code false}, bootstrappers will only fetch A records.
     */
    public void setIpv6Available(boolean ipv6Available) {
        this.ipv6Available = ipv6Available;
    }

    /**
     * @return whether the proxy will block AAAA requests.
     */
    public boolean isBlockIpv6() {
        return blockIpv6;
    }

    /**
     * @param blockIpv6 if {@code true}, the proxy will block AAAA requests.
     */
    public void setBlockIpv6(boolean blockIpv6) {
        this.blockIpv6 = blockIpv6;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DnsProxySettings that = (DnsProxySettings) o;
        return blockedResponseTtlSecs == that.blockedResponseTtlSecs &&
                ipv6Available == that.ipv6Available &&
                blockIpv6 == that.blockIpv6 &&
                Objects.equals(upstreams, that.upstreams) &&
                Objects.equals(dns64, that.dns64) &&
                longSparseArraysEqual(filterParams, that.filterParams) &&
                Objects.equals(listeners, that.listeners);
    }

    @Override
    public int hashCode() {
        return Objects.hash(upstreams, dns64, blockedResponseTtlSecs, filterParams, listeners, ipv6Available, blockIpv6);
    }

    // For testing settings marshalling
    // LongSparseArray doesn't override equals() >:\
    private static boolean longSparseArraysEqual(LongSparseArray a, LongSparseArray b) {
        if (a == null || b == null) {
            return a == b;
        }

        final int aSize = a.size();
        final int bSize = b.size();
        if (aSize != bSize) {
            return false;
        }

        for (int i = 0; i < aSize; ++i) {
            if (!Objects.equals(a.keyAt(i), b.keyAt(i))) {
                return false;
            }
            if (!Objects.equals(a.valueAt(i), b.valueAt(i))) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return the default DNS proxy settings.
     */
    public static DnsProxySettings getDefault() {
        return DnsProxy.getDefaultSettings();
    }
}
