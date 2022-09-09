using System.Collections.Generic;
using System.Net;
using AdGuard.Utils.Interop;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Upstream options.
    /// Managed mirror of <see cref="AGDnsApi.ag_upstream_options"/>
    /// </summary>
    public class UpstreamOptions
    {
        /// <summary>
        /// Server address, one of the following kinds:
        /// 8.8.8.8:53 -- plain DNS
        /// tcp://8.8.8.8:53 -- plain DNS over TCP
        /// tls://1.1.1.1 -- DNS-over-TLS
        /// https://dns.adguard.com/dns-query -- DNS-over-HTTPS
        /// sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
        /// quic://dns.adguard.com:853 -- DNS-over-QUIC
        /// </summary>
        [ManualMarshalStringToPtr]
        public string Address { get; set; }

        /// <summary>
        /// List of plain DNS servers to be used to resolve DOH/DOT hostnames (if any)
        /// </summary>
        public List<string> Bootstrap { get; set; }

        /// <summary>
        /// Default upstream timeout in milliseconds. Also, it is used as a timeout for bootstrap DNS requests.
        /// <code>timeout = 0</code>"/> means infinite timeout.
        /// </summary>
        public uint TimeoutMs { get; set; }

        /// <summary>
        /// Resolver's IP address. In the case if it's specified, bootstrap DNS servers won't be used at all.
        /// </summary>
        public IPAddress ResolvedIpAddress { get; set; }

        /// <summary>
        /// User-provided ID for this upstream
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Index of the network interface to route traffic through, 0 is default
        /// </summary>
        public uint OutboundInterfaceIndex { get; set; }
    }
}