using AdGuard.Utils.Interop;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// A managed mirror of <see cref="AGDnsApi.ag_outbound_proxy_auth_info"/>
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

        #region Equals members

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj))
            {
                return false;
            }

            if (ReferenceEquals(this, obj))
            {
                return true;
            }

            if (obj.GetType() != typeof(OutboundProxyAuthInfo))
            {
                return false;
            }

            return Equals((OutboundProxyAuthInfo)obj);
        }

        private bool Equals(OutboundProxyAuthInfo other)
        {
            return Username == other.Username && Password == other.Password;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((Username != null ? Username.GetHashCode() : 0) * 397) ^ (Password != null ? Password.GetHashCode() : 0);
            }
        }

        #endregion
    }
}