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
    /** DNS original answer's string representation */
    private String originalAnswer;
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

    public void setUpstreamAddr(String upstreamAddr) {
        this.upstreamAddr = upstreamAddr;
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
