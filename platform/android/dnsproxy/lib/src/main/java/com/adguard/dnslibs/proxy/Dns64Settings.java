package com.adguard.dnslibs.proxy;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class Dns64Settings {
    private List<UpstreamSettings> upstreams = new ArrayList<>();
    private long maxTries;
    private long waitTimeMs;

    /**
     * @return The upstreams to use for discovery of DNS64 prefixes.
     */
    public List<UpstreamSettings> getUpstreams() {
        return upstreams;
    }

    /**
     * @param upstreams The upstreams to use for discovery of DNS64 prefixes.
     */
    public void setUpstreams(List<UpstreamSettings> upstreams) {
        this.upstreams = new ArrayList<>(upstreams);
    }

    /**
     * @return How many times, at most, to try DNS64 prefixes discovery before giving up.
     */
    public long getMaxTries() {
        return maxTries;
    }

    /**
     * @param maxTries How many times, at most, to try DNS64 prefixes discovery before giving up.
     */
    public void setMaxTries(long maxTries) {
        this.maxTries = maxTries;
    }

    /**
     * @return How long to wait, in milliseconds, before a dns64 prefixes discovery attempt.
     */
    public long getWaitTimeMs() {
        return waitTimeMs;
    }

    /**
     * @param waitTimeMs How long to wait, in milliseconds, before a dns64 prefixes discovery attempt.
     */
    public void setWaitTimeMs(long waitTimeMs) {
        this.waitTimeMs = waitTimeMs;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Dns64Settings that = (Dns64Settings) o;
        return maxTries == that.maxTries &&
                waitTimeMs == that.waitTimeMs &&
                Objects.equals(upstreams, that.upstreams);
    }

    @Override
    public int hashCode() {
        return Objects.hash(upstreams, maxTries, waitTimeMs);
    }
}
