using System;
using System.Collections.Generic;
using AdGuard.Utils.Adapters.Interop;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Defines the various configuration options that can be used to specify an outbound proxy.
    /// (A managed mirror of <see cref="AGDnsApi.ag_outbound_proxy_settings"/>)
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
        /// List of the DNS server URLs to be used to resolve a hostname in the proxy server address.
        /// The URLs MUST contain the resolved server addresses, not hostnames.
        /// E.g. `https://94.140.14.14` is correct, while `dns.adguard.com:53` is not.
        /// MUST NOT be empty in case the `address` is a hostname.
        /// </summary>
        public List<string> Bootstrap { get; set; }

        /// <summary>
        /// The authentication information
        /// </summary>
        public OutboundProxyAuthInfo AuthInfo { get; set; }

        /// <summary>
        /// If true and the proxy connection is secure, the certificate won't be verified
        /// </summary>
        public bool TrustAnyCertificate { get; set; }

        /// <summary>
        /// Whether the DNS proxy should ignore the outbound proxy and route queries directly
        /// to target hosts even if it's determined as unavailable
        /// This option is only for ANDROID
        /// see more in https://jira.adguard.com/browse/AG-15207
        /// </summary>
        public bool IgnoreIfUnavailable { get; set; }
    }
}