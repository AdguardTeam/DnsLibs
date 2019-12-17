package com.adguard.dnslibs.proxy;

import java.util.Objects;

public class Dns64Settings {
    private UpstreamSettings upstream;
    private long maxTries;
    private long waitTime;

    /**
     * @return The upstream to use for discovery of DNS64 prefixes.
     */
    public UpstreamSettings getUpstream() {
        return upstream;
    }

    /**
     * @param upstream The upstream to use for discovery of DNS64 prefixes.
     */
    public void setUpstream(UpstreamSettings upstream) {
        this.upstream = upstream;
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
    public long getWaitTime() {
        return waitTime;
    }

    /**
     * @param waitTime How long to wait, in milliseconds, before a dns64 prefixes discovery attempt.
     */
    public void setWaitTime(long waitTime) {
        this.waitTime = waitTime;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Dns64Settings that = (Dns64Settings) o;
        return maxTries == that.maxTries &&
                waitTime == that.waitTime &&
                Objects.equals(upstream, that.upstream);
    }

    @Override
    public int hashCode() {
        return Objects.hash(upstream, maxTries, waitTime);
    }
}
