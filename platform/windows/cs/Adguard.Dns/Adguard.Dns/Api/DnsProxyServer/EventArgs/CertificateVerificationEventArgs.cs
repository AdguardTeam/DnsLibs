using System.Collections.Generic;

namespace Adguard.Dns.Api.DnsProxyServer.EventArgs
{
    /// <summary>
    /// onBeforeRequest event data
    /// </summary>
    /// <see cref="AGDnsApi.ag_certificate_verification_event"/>
    public class CertificateVerificationEventArgs
    {
        /// <summary>
        /// The certificate being verified
        /// </summary>
        public byte[] Certificate { get; set; }
        
        /// <summary>
        /// The certificate chain
        /// </summary>
        public List<byte[]> Chain { get; set; }
    }
}