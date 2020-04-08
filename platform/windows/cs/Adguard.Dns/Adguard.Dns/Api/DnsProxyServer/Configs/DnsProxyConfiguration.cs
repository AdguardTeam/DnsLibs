using Adguard.Dns.Api.DnsProxyServer.Callbacks;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Main configuration for the DNS libs api
    /// </summary>
    public class DnsProxyConfiguration
    {
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

            if (obj.GetType() != typeof(DnsProxyConfiguration))
            {
                return false;
            }

            return Equals((DnsProxyConfiguration)obj);
        }

        private bool Equals(DnsProxyConfiguration other)
        {
            return Equals(DnsProxySettings, other.DnsProxySettings);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = (DnsProxySettings != null ? DnsProxySettings.GetHashCode() : 0);
                return hashCode;
            }
        }
        
        #endregion
    }
}