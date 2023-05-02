using System.Collections.Generic;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;

namespace Adguard.Dns.Api.DnsProxyServer.EventArgs
{
    /// <summary>
    /// <see cref="ICertificateVerificationCallback.OnCertificateVerification"/> event data
    /// Represents an event generated during certificate verification.
    /// (A managed mirror of <see cref="AGDnsApi.ag_certificate_verification_event"/>)
    /// </summary>
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