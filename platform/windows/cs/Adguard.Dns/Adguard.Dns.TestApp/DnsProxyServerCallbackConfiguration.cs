using System;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.EventArgs;

namespace Adguard.Dns.TestApp
{
    public class DnsProxyServerCallbackConfiguration : IDnsProxyServerCallbackConfiguration
    {
        public void OnDnsRequestProcessed(object sender, DnsRequestProcessedEventArgs args)
        {
            Console.Out.WriteLine("OnDnsRequestProcessed called, args - {0}", args);
        }

        public AGDnsApi.ag_certificate_verification_result OnCertificateVerification(object sender, CertificateVerificationEventArgs args)
        {
            Console.Out.WriteLine("OnCertificateVerification called, args - {0}", args);
            return AGDnsApi.ag_certificate_verification_result.AGCVR_OK;
        }
    }
}