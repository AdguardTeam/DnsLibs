using System.Collections.Generic;
using System.Net;
using AdGuard.Utils.Base.Interop;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Represents options for configuring an upstream DNS server.
    /// Defines the various configuration options that can be used to specify an upstream DNS server.
    /// By adjusting the values of these fields, users can fine-tune the behavior of the DNS proxy
    /// server when sending DNS queries to upstream servers.
    /// (A managed mirror of <see cref="AGDnsApi.ag_upstream_options"/>)
    /// </summary>
    public class UpstreamOptions
    {
        /// <summary>
        /// Server address.
        /// One of the following kinds:
        ///  `8.8.8.8:53` -- plain DNS (must specify IP address, not hostname)
        ///  `tcp://8.8.8.8:53` -- plain DNS over TCP (must specify IP address, not hostname)
        ///  `tls://dns.adguard.com` -- DNS-over-TLS-HTTPS
        ///  `https://dns.adguard.com/dns-query` -- DNS-over-HTTPS.info/stamps-specifications)
        ///  `sdns://...` -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
        /// </summary>
        [ManualMarshalStringToPtr]
        public string Address { get; set; }

        /// <summary>
        /// List of plain DNS servers.
        /// List used to resolve the hostname in the upstream's address when necessary.
        /// These servers will help establish the initial connection to the upstream DNS server
        /// if its address is specified as a hostname.
        /// </summary>
        public List<string> Bootstrap { get; set; }

        /// <summary>
        /// Upstream's IP address.
        /// Pre-resolved IP address for the upstream server. If this field is specified, the @ref bootstrap
        /// DNS servers won't be used for resolving the upstream's address.
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
        
        /// <summary>
        /// (Optional) List of upstreams base64 encoded SPKI fingerprints to verify. If at least one of them is matched in the
        /// certificate chain, the verification will be successful
        /// </summary>
        public List<string> Fingerprints { get; set; }
    }
}