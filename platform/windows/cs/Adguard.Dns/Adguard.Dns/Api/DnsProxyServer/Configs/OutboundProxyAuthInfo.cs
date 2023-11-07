using AdGuard.Utils.Base.Interop;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Defines the fields for the authentication information used with an outbound proxy.
    /// (A managed mirror of <see cref="AGDnsApi.ag_outbound_proxy_auth_info"/>)
    /// </summary>
    public class OutboundProxyAuthInfo
    {
        /// <summary>
        /// Username
        /// </summary>
        [ManualMarshalStringToPtr]
        public string Username { get; set; }

        /// <summary>
        /// Password
        /// </summary>
        [ManualMarshalStringToPtr]
        public string Password { get; set; }
    }
}