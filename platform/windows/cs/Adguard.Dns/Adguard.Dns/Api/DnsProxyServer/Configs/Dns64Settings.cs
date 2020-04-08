using System.Collections.Generic;
using Adguard.Dns.Utils;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Dns 64 settings,
    /// managed mirror of <see cref="AGDnsApi.ag_dns64_settings"/>
    /// </summary>
    public class Dns64Settings
    {
        /// <summary>
        /// The upstreams to use for discovery of DNS64 prefixes.
        /// </summary>
        public List<UpstreamOptions> Upstreams { get; set; }
        
        /// <summary>
        /// How many times, at most, to try DNS64 prefixes discovery before giving up.
        /// </summary>
        public uint MaxTries { get; set; }
        
        /// <summary>
        /// How long to wait, in milliseconds, before a pDns64 prefixes discovery attempt.
        /// </summary>
        public uint WaitTimeMs { get; set; }

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

            if (obj.GetType() != typeof(Dns64Settings))
            {
                return false;
            }

            return Equals((Dns64Settings)obj);
        }

        private bool Equals(Dns64Settings other)
        {
            return CollectionUtils.SequenceEqual(Upstreams, other.Upstreams) && 
                   MaxTries == other.MaxTries && 
                   WaitTimeMs == other.WaitTimeMs;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = (Upstreams != null ? Upstreams.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ MaxTries.GetHashCode();
                hashCode = (hashCode * 397) ^ WaitTimeMs.GetHashCode();
                return hashCode;
            }
        }
        
        #endregion
    }
}