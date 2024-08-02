package com.adguard.dnslibs.proxy;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class DnsProxySettings {
    /**
     * Specifies how to respond to blocked requests.
     *
     * A request is blocked if it matches a blocking AdBlock-style rule,
     * or a blocking hosts-style rule. A blocking hosts-style rule is
     * a hosts-style rule with a loopback or all-zeroes address.
     *
     * Requests matching a hosts-style rule with an address that is
     * neither loopback nor all-zeroes are always responded
     * with the address specified by the rule.
     */
    public enum BlockingMode {
        // MUST keep names and ordinals in sync with ag::DnsProxyBlockingMode

        /** Respond with REFUSED response code */
        REFUSED(4),

        /** Respond with NXDOMAIN response code */
        NXDOMAIN(1),

        /**
         * Respond with an address that is all zeroes, or
         * a custom blocking address, if it is specified, or
         * an empty SOA response if request type is not A/AAAA.
         */
        ADDRESS(2),

        /**
         * response with an address that is all zeroes
         * regardless of the custom blocking address settings,
         * or an empty SOA response if request type is not A/AAAA.
         */
        UNSPECIFIED_ADDRESS(5);

        private final int code;
        BlockingMode(int code) { this.code = code; }

        public int getCode() { return code; }

        public static BlockingMode fromCode(int code) {
            for (final BlockingMode m : values()) {
                if (m.code == code) {
                    return m;
                }
            }
            throw new IllegalArgumentException("code is out of range");
        }
    }

    private List<UpstreamSettings> upstreams = new ArrayList<>();
    private List<UpstreamSettings> fallbacks = new ArrayList<>();
    private List<String> fallbackDomains = new ArrayList<>();
    private boolean detectSearchDomains;
    private Dns64Settings dns64;
    private long blockedResponseTtlSecs;
    private List<FilterParams> filterParams = new ArrayList<>();
    private List<ListenerSettings> listeners = new ArrayList<>();
    private OutboundProxySettings outboundProxy;
    private boolean ipv6Available;
    private boolean blockIpv6;
    private BlockingMode adblockRulesBlockingMode;
    private BlockingMode hostsRulesBlockingMode;
    private String customBlockingIpv4;
    private String customBlockingIpv6;
    private long dnsCacheSize;
    private boolean optimisticCache;
    private boolean enableDNSSECOK;
    private boolean enableRetransmissionHandling;
    private boolean blockEch;
    private boolean enableParallelUpstreamQueries;
    private boolean enableFallbackOnUpstreamsFailure;
    private boolean enableServfailOnUpstreamsFailure;
    private boolean enableHttp3;
    private long upstreamTimeoutMs;

    /**
     * @return Maximum number of cached responses
     */
    public long getDnsCacheSize() {
        return dnsCacheSize;
    }

    /**
     * @param dnsCacheSize Maximum number of cached responses
     */
    public void setDnsCacheSize(long dnsCacheSize) {
        this.dnsCacheSize = dnsCacheSize;
    }

    /**
     * @return Custom IPv4 address to return for filtered requests
     */
    public String getCustomBlockingIpv4() {
        return customBlockingIpv4;
    }

    /**
     * @param customBlockingIpv4 Custom IPv4 address to return for blocked requests instead of all-zeroes,
     *                           must be either empty/{@code null}, or a valid IPv4 address
     */
    public void setCustomBlockingIpv4(String customBlockingIpv4) {
        this.customBlockingIpv4 = customBlockingIpv4;
    }

    /**
     * @return Custom IPv6 address to return for filtered requests
     */
    public String getCustomBlockingIpv6() {
        return customBlockingIpv6;
    }

    /**
     * @param customBlockingIpv6 Custom IPv6 address to return for blcoked requests instead of all-zeroes,
     *                           must be either empty/{@code null}, or a valid IPv6 address
     */
    public void setCustomBlockingIpv6(String customBlockingIpv6) {
        this.customBlockingIpv6 = customBlockingIpv6;
    }

    /**
     * @return How to respond to requests blocked by AdBlock-style rules.
     */
    public BlockingMode getAdblockRulesBlockingMode() {
        return adblockRulesBlockingMode;
    }

    /**
     * @param adblockRulesBlockingMode How to respond to requests blocked by AdBlock-style rules.
     */
    public void setAdblockRulesBlockingMode(BlockingMode adblockRulesBlockingMode) {
        this.adblockRulesBlockingMode = adblockRulesBlockingMode;
    }

    /**
     * @return How to respond to requests blocked by hosts-style rules.
     */
    public BlockingMode getHostsRulesBlockingMode() {
        return hostsRulesBlockingMode;
    }

    /**
     * @param hostsRulesBlockingMode How to respond to requests blocked by hosts-style rules.
     */
    public void setHostsRulesBlockingMode(BlockingMode hostsRulesBlockingMode) {
        this.hostsRulesBlockingMode = hostsRulesBlockingMode;
    }

    /**
     * @return DNS upstreams settings list.
     */
    public List<UpstreamSettings> getUpstreams() {
        return upstreams;
    }

    /**
     * @param upstreams DNS upstreams settings list.
     */
    public void setUpstreams(List<UpstreamSettings> upstreams) {
        this.upstreams = new ArrayList<>(upstreams);
    }

    /**
     * @return Fallback DNS upstreams settings list.
     */
    public List<UpstreamSettings> getFallbacks() {
        return fallbacks;
    }

    /**
     * @param fallbacks Fallback DNS upstreams settings list.
     */
    public void setFallbacks(List<UpstreamSettings> fallbacks) {
        this.fallbacks = new ArrayList<>(fallbacks);
    }

    /**
     * @return the fallback domains
     */
    public List<String> getFallbackDomains() {
        return fallbackDomains;
    }

    /**
     * @param fallbackDomains Requests for these domains will be forwarded directly to the
     *                        fallback upstreams, if there are any. A wildcard character, `*`,
     *                        which stands for any number of characters, is allowed to appear
     *                        multiple times anywhere except at the end of the domain.
     */
    public void setFallbackDomains(List<String> fallbackDomains) {
        this.fallbackDomains = new ArrayList<>(fallbackDomains);
    }

    /**
     * @return whether search domains detection is enabled
     */
    public boolean isDetectSearchDomains() {
        return detectSearchDomains;
    }

    /**
     * @param detectSearchDomains if true, DNS search domains will be detected
     *                            and appended to the fallback filter automatically
     */
    public void setDetectSearchDomains(boolean detectSearchDomains) {
        this.detectSearchDomains = detectSearchDomains;
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
     * @return Filter engine parameters.
     */
    public List<FilterParams> getFilterParams() {
        return filterParams;
    }

    /**
     * @param filterParams Filter engine parameters.
     */
    public void setFilterParams(List<FilterParams> filterParams) {
        this.filterParams = new ArrayList<>(filterParams);
    }

    /**
     * @param filterParams Filter id -> filter data.
     * @param inMemory     If true, data is rules, otherwise data is path to file with rules.
     */
    public void setFilterParams(Map<Integer, String> filterParams, boolean inMemory) {
        this.filterParams = new ArrayList<>(filterParams.size());
        for (final Map.Entry<Integer, String> e : filterParams.entrySet()) {
            getFilterParams().add(new FilterParams(e.getKey(), e.getValue(), inMemory));
        }
    }

    /**
     * @return List of addresses/ports/protocols/etc... to listen on.
     */
    public List<ListenerSettings> getListeners() {
        return listeners;
    }

    /**
     * @param listeners List of addresses/ports/protocols/etc... to listen on.
     */
    public void setListeners(List<ListenerSettings> listeners) {
        this.listeners = new ArrayList<>(listeners);
    }

    /**
     * @return Outbound proxy settings.
     */
    public OutboundProxySettings getOutboundProxy() {
        return outboundProxy;
    }

    /**
     * @param outboundProxy Outbound proxy settings.
     */
    public void setOutboundProxy(OutboundProxySettings outboundProxy) {
        this.outboundProxy = outboundProxy;
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

    /**
     * @return whether optimistic cache is enabled
     */
    public boolean isOptimisticCache() {
        return optimisticCache;
    }

    /**
     * @param optimisticCache enable optimistic cache
     */
    public void setOptimisticCache(boolean optimisticCache) {
        this.optimisticCache = optimisticCache;
    }

    /**
     * @return Enabled log extending for responses which processed with DNSSEC or not
     */
    public boolean isEnabledDNSSECOK() {
        return enableDNSSECOK;
    }

    /**
     * @param enableDNSSECOK Enable DNSSEC OK extension.
     *                       This options tells server that we want to receive DNSSEC records along with normal queries.
     *                       If they exist, request processed event will have DNSSEC flag on.
     *                       WARNING: may increase data usage and probability of TCP fallbacks.
     */
    public void enableDNSSECOK(boolean enableDNSSECOK) {
        this.enableDNSSECOK = enableDNSSECOK;
    }

    /**
     * @return whether retransmission handling is enabled.
     */
    public boolean isEnableRetransmissionHandling() {
        return enableRetransmissionHandling;
    }

    /**
     * @param enableRetransmissionHandling if true, retransmitted requests will be handled
     *                                     using the fallback upstreams only.
     */
    public void setEnableRetransmissionHandling(boolean enableRetransmissionHandling) {
        this.enableRetransmissionHandling = enableRetransmissionHandling;
    }

    /**
     * @return whether stripping of Encrypted Client Hello parameters is enabled.
     */
    public boolean isBlockEch() {
        return blockEch;
    }

    /**
     * @param blockEch if true, Encrypted Client Hello parameters will be striped from responses.
     */
    public void setBlockEch(boolean blockEch) {
        this.blockEch = blockEch;
    }

    /**
     * @return whether parallel upstream queriying is enabled.
     */
    public boolean isEnableParallelUpstreamQueries() {
        return enableParallelUpstreamQueries;
    }

    /**
     * @param enableParallelUpstreamQueries whether to enable parallel upstream querying.
     */
    public void setEnableParallelUpstreamQueries(boolean enableParallelUpstreamQueries) {
        this.enableParallelUpstreamQueries = enableParallelUpstreamQueries;
    }

    /**
     * @return whether switching to fallback upstreams on normal upstreams failure is enabled.
     */
    public boolean isEnableFallbackOnUpstreamsFailure() {
        return enableFallbackOnUpstreamsFailure;
    }

    /**
     * @param enableFallbackOnUpstreamsFailure whether to switch to fallback upstreams when normal upstreams fail
     *                                         to provide a response.
     */
    public void setEnableFallbackOnUpstreamsFailure(boolean enableFallbackOnUpstreamsFailure) {
        this.enableFallbackOnUpstreamsFailure = enableFallbackOnUpstreamsFailure;
    }

    /**
     * @return whether generating a SERVFAIL response on upstreams failure is enabled.
     */
    public boolean isEnableServfailOnUpstreamsFailure() {
        return enableServfailOnUpstreamsFailure;
    }

    /**
     * @param enableServfailOnUpstreamsFailure whether to enable generating a SERVFAIL response when all upstreams
     *                                         (including fallback) fail to provide a response. If {@code false},
     *                                         no response will be sent to the client if no upstreams could provide
     *                                         a response.
     */
    public void setEnableServfailOnUpstreamsFailure(boolean enableServfailOnUpstreamsFailure) {
        this.enableServfailOnUpstreamsFailure = enableServfailOnUpstreamsFailure;
    }

    /**
     * @return Whether HTTP/3 support is enabled DNS-over-HTTPS upstreams.
     */
    public boolean isEnableHttp3() {
        return enableHttp3;
    }

    /**
     * @param enableHttp3 Enable HTTP/3 for DNS-over-HTTPS upstreams if it's able to connect quicker.
     */
    public void setEnableHttp3(boolean enableHttp3) {
        this.enableHttp3 = enableHttp3;
    }

    /**
     * @return Maximum amount of time, in milliseconds, allowed for upstream exchange.
     */
    public long getUpstreamTimeoutMs() {
        return upstreamTimeoutMs;
    }

    /**
     * @param upstreamTimeoutMs Maximum amount of time, in milliseconds, allowed for upstream exchange.
     */
    public void setUpstreamTimeoutMs(long upstreamTimeoutMs) {
        this.upstreamTimeoutMs = upstreamTimeoutMs;
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
                Objects.equals(fallbacks, that.fallbacks) &&
                Objects.equals(fallbackDomains, that.fallbackDomains) &&
                detectSearchDomains == that.detectSearchDomains &&
                Objects.equals(dns64, that.dns64) &&
                Objects.equals(filterParams, that.filterParams) &&
                Objects.equals(listeners, that.listeners) &&
                Objects.equals(outboundProxy, that.outboundProxy) &&
                adblockRulesBlockingMode == that.adblockRulesBlockingMode &&
                hostsRulesBlockingMode == that.hostsRulesBlockingMode &&
                Objects.equals(customBlockingIpv4, that.customBlockingIpv4) &&
                Objects.equals(customBlockingIpv6, that.customBlockingIpv6) &&
                dnsCacheSize == that.dnsCacheSize &&
                optimisticCache == that.optimisticCache &&
                enableDNSSECOK == that.enableDNSSECOK &&
                enableRetransmissionHandling == that.enableRetransmissionHandling &&
                blockEch == that.blockEch &&
                enableParallelUpstreamQueries == that.enableParallelUpstreamQueries &&
                enableFallbackOnUpstreamsFailure == that.enableFallbackOnUpstreamsFailure &&
                enableServfailOnUpstreamsFailure == that.enableServfailOnUpstreamsFailure &&
                upstreamTimeoutMs == that.upstreamTimeoutMs;
    }

    @Override
    public int hashCode() {
        return Objects.hash(upstreams, fallbacks, fallbackDomains, detectSearchDomains, dns64, blockedResponseTtlSecs,
                filterParams, listeners, outboundProxy, ipv6Available, blockIpv6, adblockRulesBlockingMode, hostsRulesBlockingMode,
                customBlockingIpv4, customBlockingIpv6,
                dnsCacheSize, optimisticCache, enableDNSSECOK, enableRetransmissionHandling, blockEch,
                enableParallelUpstreamQueries, enableFallbackOnUpstreamsFailure, enableServfailOnUpstreamsFailure,
                upstreamTimeoutMs);
    }

    /**
     * @return the default DNS proxy settings.
     */
    public static DnsProxySettings getDefault() {
        return DnsProxy.getDefaultSettings();
    }
}
