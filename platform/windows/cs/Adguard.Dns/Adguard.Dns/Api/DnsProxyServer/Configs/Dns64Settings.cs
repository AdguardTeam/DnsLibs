using System.Collections.Generic;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Dns 64 settings,
    /// Managed mirror of <see cref="AGDnsApi.ag_dns64_settings"/>
    /// </summary>
    public class Dns64Settings
    {
        /// <summary>
        /// The upstreams to use for discovery of DNS64 prefixes.
        /// </summary>
        public List<UpstreamOptions> Upstreams { get; set; }

        /// <summary>
        /// How many times, at most, to try DNS64 prefixes discovery before giving up.
        /// </summary>
        public uint MaxTries { get; set; }

        /// <summary>
        /// How long to wait, in milliseconds, before a pDns64 prefixes discovery attempt.
        /// </summary>
        public uint WaitTimeMs { get; set; }
    }
}