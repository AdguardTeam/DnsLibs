using System.Collections.Generic;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Filter engine parameters.
    /// Managed mirror of <see cref="AGDnsApi.ag_filter_engine_params"/>
    /// </summary>
    public class EngineParams
    {
        /// <summary>
        /// Filter parameters, represented as a hash-map, where
        /// "key" is the filter's identifier
        /// "value" is the filter's download path
        /// </summary>
        public List<FilterParams> FilterParams { get; set; }
    }
}