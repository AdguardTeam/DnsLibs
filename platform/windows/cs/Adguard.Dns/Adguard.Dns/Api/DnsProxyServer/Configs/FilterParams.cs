using AdGuard.Utils.Interop;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Filter parameters.
    /// Managed mirror of <see cref="AGDnsApi.ag_filter_params"/>
    /// </summary>
    public class FilterParams
    {
        /// <summary>
        /// Filter ID
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Path to the filter list file or string with rules, depending on value of in_memory
        /// </summary>
        [ManualMarshalStringToPtr]
        public string Data { get; set; }

        /// <summary>
        /// If true, data is rules, otherwise data is path to file with rules
        /// </summary>
        public bool InMemory { get; set; }

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

            if (obj.GetType() != typeof(FilterParams))
            {
                return false;
            }

            return Equals((FilterParams)obj);
        }

        private bool Equals(FilterParams other)
        {
            return Id == other.Id &&
                   Data == other.Data &&
                   InMemory == other.InMemory;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = Id;
                hashCode = (hashCode * 397) ^ (Data != null ? Data.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ InMemory.GetHashCode();
                return hashCode;
            }
        }

        #endregion
    }
}