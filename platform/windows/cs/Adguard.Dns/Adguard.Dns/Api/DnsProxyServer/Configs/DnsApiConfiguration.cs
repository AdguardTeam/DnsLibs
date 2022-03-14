using Adguard.Dns.Api.DnsProxyServer.Callbacks;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Main configuration for the DNS libs api
    /// </summary>
    public class DnsApiConfiguration
    {
        /// <summary>
        /// Gets or sets value, whether the DNS filtering is enabled of not
        /// </summary>
        public bool IsEnabled { get; set; }

        /// <summary>
        /// DNS proxy settings
        /// (<seealso cref="DnsProxySettings"/>)
        /// </summary>
        public DnsProxySettings DnsProxySettings { get; set; }

        /// <summary>
        /// DNS proxy server callback configuration
        /// </summary>
        public IDnsProxyServerCallbackConfiguration DnsProxyServerCallbackConfiguration { get; set; }
    }
}