using Adguard.Dns.Helpers;

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
        public bool InMemory;
    }
}