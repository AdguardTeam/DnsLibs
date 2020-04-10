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
    /** DNS answer's status */
    private String status;
    /** DNS Answers string representation */
    private String answer;
    /** If blocked by CNAME, here will be DNS original answer's string representation */
    private String originalAnswer;
    /** ID of the upstream that provided this answer */
    private Integer upstreamId;
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
    /** True if this response was served from the cache */
    private boolean cacheHit;

    public boolean isCacheHit() {
        return cacheHit;
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

    public String getStatus() {
        return status;
    }

    public String getAnswer() {
        return answer;
    }

    public String getOriginalAnswer() {
        return originalAnswer;
    }

    public Integer getUpstreamId() {
        return upstreamId;
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

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setStartTime(long startTime) {
        this.startTime = startTime;
    }

    public void setElapsed(int elapsed) {
        this.elapsed = elapsed;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public void setAnswer(String answer) {
        this.answer = answer;
    }

    public void setOriginalAnswer(String originalAnswer) {
        this.originalAnswer = originalAnswer;
    }

    public void setUpstreamId(Integer upstreamId) {
        this.upstreamId = upstreamId;
    }

    public void setBytesSent(int bytesSent) {
        this.bytesSent = bytesSent;
    }

    public void setBytesReceived(int bytesReceived) {
        this.bytesReceived = bytesReceived;
    }

    public void setRules(List<String> rules) {
        this.rules = rules;
    }

    public void setFilterListIds(int[] filterListIds) {
        this.filterListIds = filterListIds;
    }

    public void setWhitelist(boolean whitelist) {
        this.whitelist = whitelist;
    }

    public void setError(String error) {
        this.error = error;
    }

    public void setCacheHit(boolean cacheHit) {
        this.cacheHit = cacheHit;
    }

    @Override
    public String toString() {
        return "DnsRequestProcessedEvent{" +
                "domain='" + domain + '\'' +
                ", type='" + type + '\'' +
                ", startTime=" + startTime +
                ", elapsed=" + elapsed +
                ", status='" + status + '\'' +
                ", answer='" + answer + '\'' +
                ", originalAnswer='" + originalAnswer + '\'' +
                ", upstreamId=" + upstreamId +
                ", bytesSent=" + bytesSent +
                ", bytesReceived=" + bytesReceived +
                ", rules=" + rules +
                ", filterListIds=" + Arrays.toString(filterListIds) +
                ", whitelist=" + whitelist +
                ", error='" + error + '\'' +
                ", cacheHit=" + cacheHit +
                '}';
    }
}
