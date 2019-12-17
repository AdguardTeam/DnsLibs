package com.adguard.dnslibs.proxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DnsRequestProcessedEvent {
    /** Queried domain name */
    private String domain;
    /** Query type */
    private String type;
    /** Time when dnsproxy started processing request (epoch in milliseconds) */
    private long startTime;
    /** Time elapsed on processing (in milliseconds) */
    private int elapsed;
    /** DNS Answers string representation */
    private String answer;
    /** Address of the upstream used to resolve */
    private String upstreamAddr;
    /** Number of bytes sent to a server */
    private int bytesSent;
    /** Number of bytes received from a server */
    private int bytesReceived;
    /** Filtering rules texts */
    private List<String> rules = new ArrayList<>();
    /** Filter lists IDs of corresponding rules */
    private int[] filterListIds;
    /** True if filtering rule is whitelist */
    private boolean whitelist;
    /** If not {@code null}, contains the error text (occurred while processing the DNS query) */
    private String error;

    private DnsRequestProcessedEvent() {
        // Initialized from native code
    }

    public String getDomain() {
        return domain;
    }

    public String getType() {
        return type;
    }

    public long getStartTime() {
        return startTime;
    }

    public int getElapsed() {
        return elapsed;
    }

    public String getAnswer() {
        return answer;
    }

    public String getUpstreamAddr() {
        return upstreamAddr;
    }

    public int getBytesSent() {
        return bytesSent;
    }

    public int getBytesReceived() {
        return bytesReceived;
    }

    public List<String> getRules() {
        return rules;
    }

    public int[] getFilterListIds() {
        return filterListIds;
    }

    public boolean isWhitelist() {
        return whitelist;
    }

    public String getError() {
        return error;
    }

    @Override
    public String toString() {
        return "DnsRequestProcessedEvent{" +
                "domain='" + domain + '\'' +
                ", type='" + type + '\'' +
                ", startTime=" + startTime +
                ", elapsed=" + elapsed +
                ", answer='" + answer + '\'' +
                ", upstreamAddr='" + upstreamAddr + '\'' +
                ", bytesSent=" + bytesSent +
                ", bytesReceived=" + bytesReceived +
                ", rules=" + rules +
                ", filterListIds=" + Arrays.toString(filterListIds) +
                ", whitelist=" + whitelist +
                ", error='" + error + '\'' +
                '}';
    }
}
