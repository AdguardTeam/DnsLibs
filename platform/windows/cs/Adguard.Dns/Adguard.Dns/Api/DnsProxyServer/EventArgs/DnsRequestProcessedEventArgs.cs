using System.Collections.Generic;
using AdGuard.Utils.Adapters.Interop;

namespace Adguard.Dns.Api.DnsProxyServer.EventArgs
{
    /// <summary>
    /// On request processed event data
    /// </summary>
    /// <see cref="AGDnsApi.ag_dns_request_processed_event"/>
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
        /// Time when dnsproxy started processing request (epoch in milliseconds)
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
        /// DNS Answers string representation
        /// </summary>
        [ManualMarshalStringToPtr]
        public string Answer { get; set; }

        /// <summary>
        /// If blocked by CNAME, here will be DNS original answer's string representation
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
        /// If not {@code null}, contains the error text (occurred while processing the DNS query)
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