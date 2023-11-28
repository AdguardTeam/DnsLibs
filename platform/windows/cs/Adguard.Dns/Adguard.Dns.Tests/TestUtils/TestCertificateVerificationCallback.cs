using System.Collections.Generic;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.EventArgs;
using Adguard.Dns.Provider;
using Adguard.Dns.Utils;
using NUnit.Framework;

namespace Adguard.Dns.Tests.TestUtils
{
    [TestFixture]
    class TestCertificateVerificationCallback
    {
	    private DnsLibsDllProvider m_DnsLibsDllProvider;

		[OneTimeSetUp]
	    public void SetUp()
	    {
			m_DnsLibsDllProvider = (DnsLibsDllProvider)DnsLibsDllProvider.Instance;
		}

	    [OneTimeTearDown]
	    public void TearDown()
	    {
		    m_DnsLibsDllProvider.Dispose();
	    }

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
