﻿using System.Collections.Generic;
using Adguard.Dns.Utils;
using AdGuard.Utils.Collections;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// DNS Stamp
    /// (a managed mirror of <see cref="AGDnsApi.ag_dns_stamp"/>)
    /// </summary>
    public class DnsStamp
    {
        /// <summary>
        /// Protocol
        /// </summary>
        public AGDnsApi.ag_stamp_proto_type ProtoType { get; set; }

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
                   DoHPath == other.DoHPath &&
                   CollectionUtils.CollectionsEquals(new List<byte>(PublicKey), new List<byte>(other.PublicKey)) &&
                   Hashes.Count == other.Hashes.Count &&
                   Properties == other.Properties &&
                   PrettyUrl == other.PrettyUrl &&
                   PrettierUrl == other.PrettierUrl;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = ProtoType.GetHashCode();
                hashCode = (hashCode * 397) ^ (ServerAddress != null ? ServerAddress.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (ProviderName != null ? ProviderName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (DoHPath != null ? DoHPath.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (DoHPath != null ? PublicKey.Length : 0);
                hashCode = (hashCode * 397) ^ (DoHPath != null ? Hashes.Count : 0);
                hashCode = (hashCode * 397) ^ Properties.GetHashCode();
                hashCode = (hashCode * 397) ^ (PrettyUrl != null ? PrettyUrl.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (PrettierUrl != null ? PrettierUrl.GetHashCode() : 0);
                return hashCode;
            }
        }

        #endregion
    }
}