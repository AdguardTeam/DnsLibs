namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// DNS Stamp
    /// </summary>
    public class DnsStamp
    {
        /// <summary>
        /// Protocol
        /// </summary>
        public AGDnsApi.ag_proto_type ProtoType { get; set; }
        
        /// <summary>
        /// Server address
        /// </summary>
        public string ServerAddress { get; set; }
        
        /// <summary>
        /// Provider name
        /// </summary>
        public string ProviderName { get; set; }
        
        /// <summary>
        /// Path (for DOH)
        /// </summary>
        public string DoHPath { get; set; }

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

            if (obj.GetType() != typeof(DnsStamp))
            {
                return false;
            }

            return Equals((DnsStamp)obj);
        }

        private bool Equals(DnsStamp other)
        {
            return ProtoType == other.ProtoType && 
                   Equals(ServerAddress, other.ServerAddress) && 
                   ProviderName == other.ProviderName && 
                   DoHPath == other.DoHPath;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = ProtoType.GetHashCode();
                hashCode = (hashCode * 397) ^ (ServerAddress != null ? ServerAddress.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (ProviderName != null ? ProviderName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (DoHPath != null ? DoHPath.GetHashCode() : 0);
                return hashCode;
            }
        }
        
        #endregion
    }
}