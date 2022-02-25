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

            if (obj.GetType() != typeof(DnsApiConfiguration))
            {
                return false;
            }

            return Equals((DnsApiConfiguration)obj);
        }

        private bool Equals(DnsApiConfiguration other)
        {
            return Equals(DnsProxySettings, other.DnsProxySettings) &&
                   IsEnabled == other.IsEnabled;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = (DnsProxySettings != null ? DnsProxySettings.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ IsEnabled.GetHashCode();
                return hashCode;
            }
        }

        #endregion
    }
}