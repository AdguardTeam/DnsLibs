using System;
using AdGuard.Utils.Interop;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// A managed mirror of <see cref="AGDnsApi.ag_outbound_proxy_settings"/>
    /// </summary>
    public class OutboundProxySettings
    {
        /// <summary>
        /// The proxy protocol
        /// </summary>
        public AGDnsApi.ag_outbound_proxy_protocol Protocol { get; set; }

        /// <summary>
        /// The proxy server address (must be a valid IP address)
        /// </summary>
        [ManualMarshalStringToPtr]
        public string Address { get; set; }

        /// <summary>
        /// The proxy server port
        /// </summary>
        public UInt16 Port { get; set; }

        /// <summary>
        /// The authentication information
        /// </summary>
        public OutboundProxyAuthInfo AuthInfo { get; set; }

        /// <summary>
        /// If true and the proxy connection is secure, the certificate won't be verified
        /// </summary>
        public bool TrustAnyCertificate { get; set; }

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

            if (obj.GetType() != typeof(OutboundProxySettings))
            {
                return false;
            }

            return Equals((OutboundProxySettings)obj);
        }

        private bool Equals(OutboundProxySettings other)
        {
            return Protocol == other.Protocol &&
                   Equals(Address, other.Address) &&
                   Port == other.Port &&
                   Equals(AuthInfo, other.AuthInfo) &&
                   TrustAnyCertificate == other.TrustAnyCertificate;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = (int) Protocol;
                hashCode = (hashCode * 397) ^ (Address != null ? Address.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ Port.GetHashCode();
                hashCode = (hashCode * 397) ^ (AuthInfo != null ? AuthInfo.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ TrustAnyCertificate.GetHashCode();
                return hashCode;
            }
        }

        #endregion
    }
}