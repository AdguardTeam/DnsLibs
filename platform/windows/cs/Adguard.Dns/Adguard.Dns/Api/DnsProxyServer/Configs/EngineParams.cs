using System.Collections.Generic;
using Adguard.Dns.Utils;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Filter engine parameters.
    /// </summary>
    public class EngineParams
    {
        /// <summary> 
        /// Filter files with identifiers
        /// </summary>
        public Dictionary<uint, string> FilterParams { get; set; }
        
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

            if (obj.GetType() != typeof(EngineParams))
            {
                return false;
            }

            return Equals((EngineParams)obj);
        }

        private bool Equals(EngineParams other)
        {
            return CollectionUtils.SequenceEqual(FilterParams, other.FilterParams);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = FilterParams != null ? FilterParams.GetHashCode() : 0;
                return hashCode;
            }
        }
        
        #endregion
    }
}