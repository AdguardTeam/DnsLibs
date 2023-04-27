using System.Collections.Generic;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Represents the filter engine parameters.
    /// The filters field contains an array of ag_filter_params structures,
    /// which define the parameters for individual filters used in the filter engine.
    /// (A managed mirror of <see cref="AGDnsApi.ag_filter_engine_params"/>)
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