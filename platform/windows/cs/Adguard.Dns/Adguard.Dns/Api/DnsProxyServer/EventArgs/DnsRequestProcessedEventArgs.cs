using System.Collections.Generic;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using AdGuard.Utils.Adapters.Interop;

namespace Adguard.Dns.Api.DnsProxyServer.EventArgs
{
    /// <summary>
    /// <see cref="IDnsProxyServerCallbackConfiguration.OnDnsRequestProcessed"/> event data
    /// Defines the various fields of a DNS request processed event.
    /// (A managed mirror of <see cref="AGDnsApi.ag_dns_request_processed_event"/>)
    /// </summary>
    public class DnsRequestProcessedEventArgs
    {
        /// <summary>
        /// Queried domain name
        /// </summary>
        [ManualMarshalStringToPtr]
        public string Domain { get; set; }

        /// <summary>
        /// Query type
        /// </summary>
        [ManualMarshalStringToPtr]
        public string Type { get; set; }

        /// <summary>
        /// Processing start time, in milliseconds since UNIX epoch
        /// </summary>
        public long StartTime { get; set; }

        /// <summary>
        /// Time elapsed on processing (in milliseconds)
        /// </summary>
        public int Elapsed { get; set; }

        /// <summary>
        /// DNS answer's status
        /// </summary>
        [ManualMarshalStringToPtr]
        public string Status { get; set; }

        /// <summary>
        /// A string representation of the DNS reply sent
        /// </summary>
        [ManualMarshalStringToPtr]
        public string Answer { get; set; }

        /// <summary>
        /// A string representation of the original upstream's DNS reply (present when blocked by CNAME)
        /// </summary>
        [ManualMarshalStringToPtr]
        public string OriginalAnswer { get; set; }

        /// <summary>
        /// ID of the upstream that provided this answer
        /// </summary>
        public int? UpstreamId { get; set; }

        /// <summary>
        /// Number of bytes sent to a server
        /// </summary>
        public int BytesSent { get; set; }

        /// <summary>
        /// Number of bytes received from a server
        /// </summary>
        public int BytesReceived { get; set; }

        /// <summary>
        /// Filtering rules texts
        /// </summary>
        public List<string> Rules { get; set; }

        /// <summary>
        /// Filter lists IDs of corresponding rules
        /// </summary>
        public List<int> FilterListIds { get; set; }

        /// <summary>
        /// True if filtering rule is whitelist
        /// </summary>
        public bool Whitelist { get; set; }

        /// <summary>
        /// If not null, contains the error text (occurred while processing the DNS query)
        /// </summary>
        [ManualMarshalStringToPtr]
        public string Error { get; set; }

        /// <summary>
        /// True if this response was served from the cache
        /// </summary>
        public bool CacheHit { get; set; }

        /// <summary>
        /// True if this response has DNSSEC rrsig
        /// </summary>
        public bool DNSSEC { get; set; }
    }
}