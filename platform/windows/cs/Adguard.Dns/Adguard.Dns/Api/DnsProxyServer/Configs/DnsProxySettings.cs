using System.Collections.Generic;
using AdGuard.Utils.Base.Interop;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Represents settings for the AdGuard DNS proxy.
    /// Defines the various configuration options that can be
    /// used to specify the AdGuard DNS proxy settings.
    /// (A managed mirror of <see cref="AGDnsApi.ag_dnsproxy_settings"/>)
    /// </summary>
    public class DnsProxySettings
    {
        /// <summary>
        /// List of upstreams representing the list of primary upstream DNS servers.
        /// The DNS proxy server will send queries to these servers.
        /// (<seealso cref="UpstreamOptions"/>)
        /// </summary>
        public List<UpstreamOptions> Upstreams { get; set; }

        /// <summary>
        /// List of fallback upstreams, representing the list of fallback upstream DNS servers.
        /// DNS proxy server will send queries to these servers
        /// if none of the primary upstreams respond.
        /// (<seealso cref="UpstreamOptions"/>)
        /// </summary>
        public List<UpstreamOptions> Fallbacks { get; set; }

        /// <summary>
        /// Requests for these domains will be forwarded directly to the fallback upstreams, if there are any.
        /// A wildcard character, `*`, which stands for any number of characters, is allowed to appear multiple
        /// times anywhere except at the end of the domain (which implies that a domain consisting only of
        /// wildcard characters is invalid).
        /// </summary>
        public List<string> FallbackDomains { get; set; }

        /// <summary>
        /// DNS64 settings.
        /// If <code>null</code>, DNS64 is disabled
        /// (<seealso cref="Dns64Settings"/>)
        /// </summary>
        public Dns64Settings Dns64 { get; set; }

        /// <summary>
        /// TTL of the record for the blocked domains (in seconds)
        /// </summary>
        public uint BlockedResponseTtlSec { get; set; }

        /// <summary>
        /// Filter engine parameters.
        /// </summary>
        public EngineParams EngineParams { get; set; }

        /// <summary>
        /// List of addresses/ports/protocols/etc... to listen on.
        /// (<seealso cref="ListenerSettings"/>)
        /// </summary>
        public List<ListenerSettings> Listeners { get; set; }

        /// <summary>
        /// Outbound proxy settings
        /// </summary>
        public OutboundProxySettings OutboundProxySettings { get; set; }

        /// <summary>
        /// Determines, whether bootstrappers will fetch AAAA records.
        /// </summary>
        public bool Ipv6Available { get; set; }

        /// <summary>
        /// Determines, whether the proxy will block AAAA requests.
        /// </summary>
        public bool BlockIpv6 { get; set; }

        /// <summary>
        /// How to respond to requests blocked by AdBlock-style rules
        /// (<see cref="AGDnsApi.ag_dnsproxy_blocking_mode"/>)
        /// </summary>
        public AGDnsApi.ag_dnsproxy_blocking_mode AdblockRulesBlockingMode { get; set; }

        /// <summary>
        /// How to respond to requests blocked by hosts-style rules
        /// (<see cref="AGDnsApi.ag_dnsproxy_blocking_mode"/>)
        /// </summary>
        public AGDnsApi.ag_dnsproxy_blocking_mode HostsRulesBlockingMode { get; set; }

        /// <summary>
        /// Custom IPv4 address to return for filtered requests,
        /// must be either empty/<code>null</code>, or a valid IPv4 address;
        /// ignored if <see cref="AdblockRulesBlockingMode"/> != <see cref="AGDnsApi.ag_dnsproxy_blocking_mode.AGBM_ADDRESS"/>
        /// </summary>
        [ManualMarshalStringToPtr]
        public string CustomBlockingIpv4 { get; set; }

        /// <summary>
        /// Custom IPv4 address to return for filtered requests,
        /// must be either empty/<code>null</code>, or a valid IPv6 address;
        /// ignored if <see cref="AdblockRulesBlockingMode"/> != <see cref="AGDnsApi.ag_dnsproxy_blocking_mode.AGBM_ADDRESS"/>
        /// </summary>
        [ManualMarshalStringToPtr]
        public string CustomBlockingIpv6 { get; set; }

        /// <summary>
        /// Maximum number of cached responses
        /// </summary>
        public uint DnsCacheSize { get; set; }
        
        /// <summary>
        /// Maximum amount of time, in milliseconds, allowed for upstream exchange (0 means default)
        /// </summary>
        public uint UpstreamTimeoutMs { get; set; }

        /// <summary>
        /// Enable optimistic DNS caching
        /// </summary>
        public bool OptimisticCache { get; set; }

        /// <summary>
        /// Enable DNSSEC OK extension.
        /// This options tells server that we want to receive DNSSEC records along with normal queries.
        /// If they exist, request processed event will have DNSSEC flag on.
        /// WARNING: may increase data usage and probability of TCP fallbacks.
        /// </summary>
        public bool EnableDNSSECOK { get; set; }

        /// <summary>
        /// If enabled, retransmitted requests will be answered using the fallback upstreams only.
        /// If a retransmitted request is detected, the original request will NOT be answered at all.
        ///
        /// Mostly intended for iOS.
        /// If enable_retransmission_handling is true,
        /// retransmitted requests
        /// (defined as requests with the same id and sent from the same address
        /// that one of the requests that are currently being handled)
        /// will be handled only using fallback upstreams, and the answer to the original
        /// request will not be sent (to prevent possibly sending SERVFAIL,
        /// b/c iOS may mark the resolver as "bad" in this case and refuse to resolve
        /// anything from that point).
        /// Enabling this feature shouldn't break anything on Android and Windows,
        /// but it should not be enabled if there are otherwise no issues with retransmitted requests.
        /// </summary>
        public bool EnableRetransmissionHandling { get; set; }

        /// <summary>
        /// If enabled, strip Encrypted Client Hello parameters from responses.
        /// </summary>
        public bool BlockEch { get; set; }

        /// <summary>
        /// If true, all upstreams are queried in parallel, and the first response is returned.
        /// </summary>
        public bool EnableParallelUpstreamQueries { get; set; }

        /// <summary>
        /// If true, normal queries will be forwarded to fallback upstreams if all normal upstreams failed.
        /// Otherwise, fallback upstreams will only be used to resolve domains from `fallback_domains`.
        /// </summary>
        public bool EnableFallbackOnUpstreamsFailure { get; set; }

        /// <summary>
        /// If true, when all upstreams (including fallback upstreams) fail to provide a response.
        /// The proxy will respond with a SERVFAIL packet. Otherwise, no response is sent on such a failure.
        /// </summary>
        public bool EnableServfailOnUpstreamsFailure { get; set; }

        /// <summary>
        /// Enable HTTP/3 for DNS-over-HTTPS upstreams if it's able to connect quicker.
        /// </summary>
        public bool EnableHttp3  { get; set; }
    }
}