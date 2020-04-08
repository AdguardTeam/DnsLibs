using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.EventArgs;
using Adguard.Dns.Logging;

namespace Adguard.Dns.Utils
{
    /// <summary>
    /// Certificate verification callbacks interface
    /// </summary>
    internal class CertificateVerificationCallback : ICertificateVerificationCallback
    {
        private static readonly ILog LOG = LogProvider.For<CertificateVerificationCallback>();
        
        /// <summary>
        /// Called synchronously when a certificate needs to be verified.
        /// Return NULL for success or an error message
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="args">Event data
        /// (<seealso cref="CertificateVerificationEventArgs"/>)</param>
        /// <returns>Certificate verification result
        /// (<seealso cref="AGDnsApi.ag_certificate_verification_result"/>)</returns>
        public AGDnsApi.ag_certificate_verification_result OnCertificateVerification(
            object sender, 
            CertificateVerificationEventArgs args)
        {
            X509Chain fullChain = new X509Chain();
            try
            {
                byte[] certificateData = args.Certificate;
                if (certificateData == null ||
                    certificateData.Length == 0)
                {
                    LOG.Info("Cannot verify certificate, because cert data is null");
                    return AGDnsApi.ag_certificate_verification_result.AGCVR_ERROR_CREATE_CERT;
                }

                X509Certificate2 certificate = new X509Certificate2(certificateData);
                List<byte[]> chainCertificatesData = args.Chain;
                if (chainCertificatesData != null &&
                    chainCertificatesData.Any())
                {
                    foreach (byte[] chainCertificateData in chainCertificatesData)
                    {
                        X509Certificate2 chainCertificate = new X509Certificate2(chainCertificateData);
                        fullChain.ChainPolicy.ExtraStore.Add(chainCertificate);
                    }
                }

                fullChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                fullChain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreWrongUsage;
                bool isChainSuccessfullyBuilt = fullChain.Build(certificate);
                if (!isChainSuccessfullyBuilt)
                {
                    LOG.Info("Cannot verify certificate, because cannot build a valid full certificate chain");
                    return AGDnsApi.ag_certificate_verification_result.AGCVR_ERROR_CERT_VERIFICATION;
                }

                return AGDnsApi.ag_certificate_verification_result.AGCVR_OK;
            }
            catch (Exception ex)
            {
                LOG.InfoException("Verification certificate fails", ex);
                return AGDnsApi.ag_certificate_verification_result.AGCVR_COUNT;
            }
        }
    }
}