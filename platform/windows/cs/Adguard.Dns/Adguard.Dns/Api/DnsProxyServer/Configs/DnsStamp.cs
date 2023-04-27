using System.Collections.Generic;
using Adguard.Dns.Utils;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Defines the various fields of a DNS stamp.
    /// (A managed mirror of <see cref="AGDnsApi.ag_dns_stamp"/>)
    /// </summary>
    public class DnsStamp
    {
        /// <summary>
        /// Protocol
        /// </summary>
        public AGDnsApi.ag_stamp_proto_type ProtoType { get; set; }

        /// <summary>
        /// IP address and/or port
        /// </summary>
        public string ServerAddress { get; set; }

        /// <summary>
        /// Provider name
        /// Provider means different things depending on the stamp type
        /// DNSCrypt: the DNSCrypt provider name
        /// DOH and DOT: server's hostname
        /// Plain DNS: not specified
        /// </summary>
        public string ProviderName { get; set; }

        /// <summary>
        /// (For DoH) absolute URI path, such as /dns-query
        /// </summary>
        public string DoHPath { get; set; }

        /// <summary>
        /// The DNSCrypt provider’s Ed25519 public key, as 32 raw bytes. Empty for other types.
        /// </summary>
        public byte[] PublicKey { get; set; }

        /// <summary>
        /// Hash is the SHA256 digest of one of the TBS certificate found in the validation chain, typically
        /// the certificate used to sign the resolver’s certificate. Multiple hashes can be provided for seamless
        /// rotations.
        /// </summary>
        public List<byte[]> Hashes { get; set; }

        /// <summary>
        /// Server properties
        /// </summary>
        public AGDnsApi.ag_server_informal_properties Properties { get; set; }

        /// <summary>
        /// A URL representation of this stamp which can be used
        /// as a valid ag_upstream_options address
        /// </summary>
        public string PrettyUrl
        {
            get
            {
                string prettyUrl = DnsUtils.GetDnsStampPrettyUrl(this);
                return prettyUrl;
            }
        }

        /// <summary>
        /// A URL representation of this stamp which is prettier,
        /// but can NOT be a valid ag_upstream_options address
        /// </summary>
        public string PrettierUrl
        {
            get
            {
                string prettierUrl = DnsUtils.GetDnsStampPrettierUrl(this);
                return prettierUrl;
            }
        }

        /// <summary>
        /// Gets the SDNS-based string representation
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            string dnsStampString = DnsUtils.GetDnsStampString(this);
            return dnsStampString;
        }
    }
}