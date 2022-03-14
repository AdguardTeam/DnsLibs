using System;
using AdGuard.Utils.Interop;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// A managed mirror of <see cref="AGDnsApi.ag_outbound_proxy_settings"/>
    /// </summary>
    public class OutboundProxySettings
    {
        /// <summary>
        /// The proxy protocol
        /// </summary>
        public AGDnsApi.ag_outbound_proxy_protocol Protocol { get; set; }

        /// <summary>
        /// The proxy server address (must be a valid IP address)
        /// </summary>
        [ManualMarshalStringToPtr]
        public string Address { get; set; }

        /// <summary>
        /// The proxy server port
        /// </summary>
        public UInt16 Port { get; set; }

        /// <summary>
        /// The authentication information
        /// </summary>
        public OutboundProxyAuthInfo AuthInfo { get; set; }

        /// <summary>
        /// If true and the proxy connection is secure, the certificate won't be verified
        /// </summary>
        public bool TrustAnyCertificate { get; set; }
    }
}