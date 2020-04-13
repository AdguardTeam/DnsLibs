using System.Collections.Generic;
using Adguard.Dns.Helpers;
using Adguard.Dns.Utils;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// DNS proxy settings,
    /// Managed mirror of <see cref="AGDnsApi.ag_dnsproxy_settings"/>
    /// </summary>
    public class DnsProxySettings
    {
        /// <summary>
        /// DNS upstreams settings list
        /// (<seealso cref="UpstreamOptions"/>)
        /// </summary>
        public List<UpstreamOptions> Upstreams { get; set; }
        
        /// <summary>
        /// Fallback DNS upstreams settings list
        /// (<seealso cref="UpstreamOptions"/>)
        /// </summary>
        public List<UpstreamOptions> Fallbacks { get; set; }
        
        /// <summary>
        /// DNS64 settings.
        /// If <code>null</code>, DNS64 is disabled
        /// (<seealso cref="Dns64Settings"/>)
        /// </summary>
        public Dns64Settings Dns64 { get; set; }
        
        /// <summary>
        /// TTL of the record for the blocked domains (in seconds)
        /// </summary>
        public uint BlockedResponseTtlSec { get; set; }
        
        /// <summary>
        /// Filter engine parameters.
        /// </summary>
        public EngineParams EngineParams { get; set; }
        
        /// <summary>
        /// List of addresses/ports/protocols/etc... to listen on.
        /// (<seealso cref="ListenerSettings"/>)
        /// </summary>
        public List<ListenerSettings> Listeners { get; set; }
        
        /// <summary>
        /// Determines, whether bootstrappers will fetch AAAA records.
        /// </summary>
        public bool Ipv6Available { get; set; }
        
        /// <summary>
        /// Determines, whether the proxy will block AAAA requests.
        /// </summary>
        public bool BlockIpv6 { get; set; }
        
        /// <summary>
        /// The blocking mode
        /// (<see cref="BlockingMode"/>)
        /// </summary>
        public AGDnsApi.ag_dnsproxy_blocking_mode BlockingMode { get; set; }
        
        /// <summary>
        /// Custom IPv4 address to return for filtered requests,
        /// must be either empty/<code>null</code>, or a valid IPv4 address;
        /// ignored if <see cref="BlockingMode"/> != <see cref="AGDnsApi.ag_dnsproxy_blocking_mode.CUSTOM_ADDRESS"/>
        /// </summary>
        [ManualMarshalStringToPtr]
        public string CustomBlockingIpv4 { get; set; }
        
        /// <summary>
        /// Custom IPv4 address to return for filtered requests,
        /// must be either empty/<code>null</code>, or a valid IPv6 address;
        /// ignored if <see cref="BlockingMode"/> != <see cref="AGDnsApi.ag_dnsproxy_blocking_mode.CUSTOM_ADDRESS"/>
        /// </summary>
        [ManualMarshalStringToPtr]
        public string CustomBlockingIpv6 { get; set; }
        
        /// <summary>
        /// Maximum number of cached responses
        /// </summary>
        public uint DnsCacheSize { get; set; }
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

            if (obj.GetType() != typeof(DnsProxySettings))
            {
                return false;
            }

            return Equals((DnsProxySettings)obj);
        }

        private bool Equals(DnsProxySettings other)
        {
            return CollectionUtils.SequenceEqual(Upstreams, other.Upstreams) && 
                   CollectionUtils.SequenceEqual(Fallbacks, other.Fallbacks) && 
                   Equals(Dns64, other.Dns64) && 
                   BlockedResponseTtlSec == other.BlockedResponseTtlSec && 
                   Equals(EngineParams, other.EngineParams) && 
                   CollectionUtils.SequenceEqual(Listeners, other.Listeners) && 
                   Ipv6Available == other.Ipv6Available && 
                   BlockIpv6 == other.BlockIpv6 && 
                   BlockingMode == other.BlockingMode && 
                   CustomBlockingIpv4 == other.CustomBlockingIpv4 && 
                   CustomBlockingIpv6 == other.CustomBlockingIpv6 && 
                   DnsCacheSize == other.DnsCacheSize;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = (Upstreams != null ? Upstreams.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (Fallbacks != null ? Fallbacks.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (Dns64 != null ? Dns64.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ BlockedResponseTtlSec.GetHashCode();
                hashCode = (hashCode * 397) ^ (EngineParams != null ? EngineParams.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (Listeners != null ? Listeners.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ Ipv6Available.GetHashCode();
                hashCode = (hashCode * 397) ^ BlockIpv6.GetHashCode();
                hashCode = (hashCode * 397) ^ BlockingMode.GetHashCode();
                hashCode = (hashCode * 397) ^ (CustomBlockingIpv4 != null ? CustomBlockingIpv4.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (CustomBlockingIpv6 != null ? CustomBlockingIpv6.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ DnsCacheSize.GetHashCode();
                return hashCode;
            }
        }
        
        #endregion
    }
}