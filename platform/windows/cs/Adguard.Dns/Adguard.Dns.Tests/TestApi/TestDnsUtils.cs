using System;
using System.Collections.Generic;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Provider;
using Adguard.Dns.Utils;
using NUnit.Framework;

namespace Adguard.Dns.Tests.TestApi
{
    [TestFixture]
    public class TestDnsUtils
    {
	    private const string VALID_DNS_STAMP = "sdns://AgcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQovZG5zLXF1ZXJ5";
	    private const string VALID_DNS_STAMP_1 = "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20";
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
        public void TesRuleValidation()
        {
            Dictionary<string, bool> ruleValidationTable = new Dictionary<string, bool>
            {
                {"||browser.events.data.microsoft.com^$dnstype=~A", true}
            };

            foreach (var pair in ruleValidationTable)
            {
                Console.WriteLine("Rule: {0}", pair.Key);
                Assert.AreEqual(DnsUtils.IsRuleValid(pair.Key), pair.Value);
            }
        }

        [Test]
        public void TestGetDnsStampString()
        {
	        DnsStamp dnsStamp = DnsUtils.ParseDnsStamp(VALID_DNS_STAMP);
	        Assert.IsNotNull(dnsStamp);
	        string dnsStampString = dnsStamp.ToString();
	        Assert.AreEqual(dnsStampString, VALID_DNS_STAMP);
        }

        [Test]
        public void TestParseValidDnsStamp()
        {
	        DnsStamp dnsStamp = DnsUtils.ParseDnsStamp(VALID_DNS_STAMP);
	        Assert.IsNotNull(dnsStamp);
	        Assert.AreEqual("127.0.0.1", dnsStamp.ServerAddress);
	        Assert.AreEqual("example.com", dnsStamp.ProviderName);
	        Assert.IsNull(dnsStamp.PublicKey);
	        Assert.AreEqual(1, dnsStamp.Hashes.Count);
			Assert.True(dnsStamp.Properties.HasValue);
			Assert.AreEqual(
				AGDnsApi.ag_server_informal_properties.AGSIP_DNSSEC |
				AGDnsApi.ag_server_informal_properties.AGSIP_NO_LOG |
				AGDnsApi.ag_server_informal_properties.AGSIP_NO_FILTER, dnsStamp.Properties);
			Assert.AreEqual("/dns-query", dnsStamp.DoHPath);
	        Assert.AreEqual("127.0.0.1", dnsStamp.ServerAddress);
	        Assert.AreEqual(AGDnsApi.ag_stamp_proto_type.DOH, dnsStamp.ProtoType);
	        Assert.AreEqual("127.0.0.1", dnsStamp.ServerAddress);
	        Assert.AreEqual("https://example.com/dns-query", dnsStamp.PrettyUrl);
	        Assert.AreEqual("https://example.com/dns-query", dnsStamp.PrettierUrl);

	        dnsStamp = DnsUtils.ParseDnsStamp(VALID_DNS_STAMP_1);
	        Assert.IsNotNull(dnsStamp);
	        Assert.IsNotNull(dnsStamp.PublicKey);
	        Assert.AreEqual(32, dnsStamp.PublicKey.Length);
        }
	}
}