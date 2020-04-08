using Adguard.Dns.Api.DnsProxyServer.EventArgs;

namespace Adguard.Dns.Api.DnsProxyServer.Callbacks
{
    /// <summary>
    /// Certificate verification callbacks interface
    /// </summary>
    internal interface ICertificateVerificationCallback
    {
        /// <summary>
        /// Called synchronously when a certificate needs to be verified.
        /// Return NULL for success or an error message
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="args">Event data
        /// (<seealso cref="CertificateVerificationEventArgs"/>)</param>
        /// <returns>Certificate verification result
        /// (<seealso cref="AGDnsApi.ag_certificate_verification_result"/>)</returns>
        AGDnsApi.ag_certificate_verification_result 
            OnCertificateVerification(object sender, CertificateVerificationEventArgs args);
    }
}