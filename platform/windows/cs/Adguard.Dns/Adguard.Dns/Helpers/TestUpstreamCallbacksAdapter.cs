using System;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.EventArgs;
using Adguard.Dns.Exceptions;

namespace Adguard.Dns.Helpers
{
    /// <summary>
    /// An adapter between the native callbacks and the managed callbacks for the <see cref="DnsProxyServer"/>
    /// </summary>
    /// <see cref="AGDnsApi.cbd_onCertificateVerification"/>
    internal class TestUpstreamCallbacksAdapter
    {
        private readonly ICertificateVerificationCallback m_CertificateVerificationCallback;
        private readonly AGDnsApi.cbd_onCertificateVerification m_OnTestUpstreamCallback;

        /// <summary>
        /// Creates an instance of the adapter
        /// </summary>
        /// <param name="certificateVerificationCallback">An object implementing the verification callback interface
        /// (<seealso cref="ICertificateVerificationCallback"/>)</param>
        internal TestUpstreamCallbacksAdapter(ICertificateVerificationCallback certificateVerificationCallback)
        {
            m_CertificateVerificationCallback = certificateVerificationCallback;
            m_OnTestUpstreamCallback = AGCOnCertificateVerification;
        }

        /// <summary>
        /// Native <see cref="AGDnsApi.cbd_onCertificateVerification"/> object
        /// </summary>
        internal AGDnsApi.cbd_onCertificateVerification OnTestUpstreamCallback
        {
            get { return m_OnTestUpstreamCallback; }
        }

        /// <summary>
        /// <see cref="AGDnsApi.cbd_onCertificateVerification"/> adapter
        /// </summary>
        /// <param name="pInfo">The pointer to an instance of
        /// <see cref="AGDnsApi.ag_certificate_verification_event"/></param>
        /// <returns>Certificate verification result
        /// (<seealso cref="AGDnsApi.ag_certificate_verification_result"/>)</returns>
        private AGDnsApi.ag_certificate_verification_result AGCOnCertificateVerification(IntPtr pInfo)
        {
            try
            {
                AGDnsApi.ag_certificate_verification_event coreArgs = 
                    MarshalUtils.PtrToStructure<AGDnsApi.ag_certificate_verification_event>(pInfo);
                CertificateVerificationEventArgs args = DnsApiConverter.FromNativeObject(coreArgs);
                AGDnsApi.ag_certificate_verification_result certificateVerificationResult = 
                    m_CertificateVerificationCallback.OnCertificateVerification(this, args);
                return certificateVerificationResult;
            }
            catch (Exception ex)
            {
                CoreExceptionHandler.HandleManagedException(ex);
                return AGDnsApi.ag_certificate_verification_result.AGCVR_ERROR_CERT_VERIFICATION;
            }
        }
    }
}