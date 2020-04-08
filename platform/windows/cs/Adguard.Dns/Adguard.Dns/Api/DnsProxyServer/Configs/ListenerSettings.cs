using System.Net;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Listener settings
    /// Managed mirror of <see cref="AGDnsApi.ag_listener_settings"/>
    /// </summary>
    public class ListenerSettings
    {
        /// <summary>
        /// The <see cref="IPEndPoint"/> to listen on
        /// </summary>
        public IPEndPoint EndPoint { get; set; }
        
        /// <summary>
        /// The protocol to listen for
        /// </summary>
        public AGDnsApi.ag_listener_protocol Protocol { get; set; }
        
        /// <summary>
        /// Don't close the TCP connection after sending the first response
        /// </summary>
        public bool IsPersistent { get; set; }
        
        /// <summary>
        /// Close the TCP connection this long after the last request received
        /// </summary>
        public int IdleTimeoutMs { get; set; }

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

            if (obj.GetType() != typeof(ListenerSettings))
            {
                return false;
            }

            return Equals((ListenerSettings)obj);
        }

        private bool Equals(ListenerSettings other)
        {
            return Equals(EndPoint, other.EndPoint) && 
                   Protocol == other.Protocol && 
                   IsPersistent == other.IsPersistent && 
                   IdleTimeoutMs == other.IdleTimeoutMs;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = (EndPoint != null ? EndPoint.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (int) Protocol;
                hashCode = (hashCode * 397) ^ IsPersistent.GetHashCode();
                hashCode = (hashCode * 397) ^ IdleTimeoutMs;
                return hashCode;
            }
        }
        
        #endregion
    }
}