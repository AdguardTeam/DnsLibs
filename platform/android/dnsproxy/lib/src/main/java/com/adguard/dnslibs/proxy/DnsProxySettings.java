package com.adguard.dnslibs.proxy;

import android.util.LongSparseArray;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class DnsProxySettings {
    private List<UpstreamSettings> upstreams = new ArrayList<>();
    private Dns64Settings dns64;
    private long blockedResponseTtl;
    private LongSparseArray<String> filterParams = new LongSparseArray<>();
    private List<ListenerSettings> listeners = new ArrayList<>();

    /**
     * @return DNS upstreams settings list.
     */
    public List<UpstreamSettings> getUpstreams() {
        return upstreams;
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
    public long getBlockedResponseTtl() {
        return blockedResponseTtl;
    }

    /**
     * @param blockedResponseTtl TTL of the record for the blocked domains (in seconds).
     */
    public void setBlockedResponseTtl(long blockedResponseTtl) {
        this.blockedResponseTtl = blockedResponseTtl;
    }

    /**
     * @return Filter engine parameters. Filter files with identifiers.
     */
    public LongSparseArray<String> getFilterParams() {
        return filterParams;
    }

    /**
     * @return List of addresses/ports/protocols/etc... to listen on.
     */
    public List<ListenerSettings> getListeners() {
        return listeners;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DnsProxySettings that = (DnsProxySettings) o;
        return blockedResponseTtl == that.blockedResponseTtl &&
                upstreams.equals(that.upstreams) &&
                Objects.equals(dns64, that.dns64) &&
                longSparseArraysEqual(filterParams, that.filterParams) &&
                listeners.equals(that.listeners);
    }

    @Override
    public int hashCode() {
        return Objects.hash(upstreams, dns64, blockedResponseTtl, filterParams, listeners);
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
