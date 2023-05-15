namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// The subset of <see cref="DnsProxySettings"/>
    /// available for overriding on a specific listener.
    /// (A managed mirror for <see cref="AGDnsApi.ag_proxy_settings_overrides"/>)
    /// </summary>
    public class ProxySettingsOverrides
    {
        /// <summary>
        /// Overrides <see cref="DnsProxySettings.BlockEch"/> if not null
        /// </summary>
        public bool? BlockEch { get; set; }
    }
}