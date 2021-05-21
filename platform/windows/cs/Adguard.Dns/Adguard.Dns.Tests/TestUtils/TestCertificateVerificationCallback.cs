using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.EventArgs;
using Adguard.Dns.Utils;
using NUnit.Framework;

namespace Adguard.Dns.Tests.TestUtils
{
    [TestFixture]
    class TestCertificateVerificationCallback
    {
        [Test]
        public void TestCertificateVerification()
        {
            byte[] certBytes = Properties.Resources.ExampleTestCertificate;
            CertificateVerificationEventArgs args = new CertificateVerificationEventArgs
            {
                Certificate = certBytes,
                Chain = new List<byte[]>
                {
                    certBytes
                }
            };
            ICertificateVerificationCallback certificateVerificationCallback = new CertificateVerificationCallback();
            AGDnsApi.ag_certificate_verification_result certificateVerificationResult =
            certificateVerificationCallback.OnCertificateVerification(this, args);
            Assert.AreEqual( AGDnsApi.ag_certificate_verification_result.AGCVR_OK, certificateVerificationResult);
        }
    }
}
