using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Provider;
using Adguard.Dns.Utils;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Adguard.Dns.Tests.TestApi
{
    [TestFixture]
    public class TestDnsUtils
    {
	    private const string VALID_DNS_STAMP = "sdns://AgcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQovZG5zLXF1ZXJ5";
	    private const string VALID_DNS_STAMP_1 = "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20";
		private const string PROVIDER_PUBLIC_KEY = "d12b47f252dcf2c2bbf8991086eaf79ce4495d8b16c8a0c4322e52ca3f390873";
	    private const string INVALID_DNS_STAMP = "sdns://AQcAAAAAAAAAGDIuZG5zY3J5cHQtY2VydC5pYmtzdHVybQAA";
	    private const string INVALID_DNS_STAMP_1 = "sdns://abcdefgh";
	    private const string VALID_DNS_ADDRESS = "8.8.8.8";
	    private const string INVALID_DNS_ADDRESS = "1.2.3";

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
        public void TestParseInvalidDnsStamp()
        {
	        DnsStamp dnsStamp = DnsUtils.ParseDnsStamp(INVALID_DNS_STAMP);
	        Assert.IsNull(dnsStamp);

	        dnsStamp = DnsUtils.ParseDnsStamp(INVALID_DNS_STAMP_1);
	        Assert.IsNull(dnsStamp);
        }

        [Test]
        public void TestParseNullDnsStamp()
        {
	        DnsStamp dnsStamp = DnsUtils.ParseDnsStamp(null);
	        Assert.IsNull(dnsStamp);
        }

        [Test]
        public void TestParseInvalidNonSDNS()
        {
	        DnsStamp dnsStamp = DnsUtils.ParseDnsStamp(INVALID_DNS_ADDRESS);
	        Assert.IsNull(dnsStamp);
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
			Assert.IsTrue(dnsStamp.Properties.HasValue);
			Assert.IsTrue((dnsStamp.Properties & AGDnsApi.ag_server_informal_properties.AGSIP_DNSSEC) != 0);
			Assert.IsTrue((dnsStamp.Properties & AGDnsApi.ag_server_informal_properties.AGSIP_NO_LOG) != 0);
			Assert.IsTrue((dnsStamp.Properties & AGDnsApi.ag_server_informal_properties.AGSIP_NO_FILTER) != 0);
			Assert.AreEqual("/dns-query", dnsStamp.DoHPath);
	        Assert.AreEqual(AGDnsApi.ag_stamp_proto_type.DOH, dnsStamp.ProtoType);
	        Assert.AreEqual("https://example.com/dns-query", dnsStamp.PrettyUrl);
	        Assert.AreEqual("https://example.com/dns-query", dnsStamp.PrettierUrl);
        }

        [Test]
        public void TestParseValidDnsStampWithPublicKey()
        {
	        DnsStamp dnsStamp = DnsUtils.ParseDnsStamp(VALID_DNS_STAMP_1);
	        Assert.IsNotNull(dnsStamp);
	        Assert.IsNotNull(dnsStamp.PublicKey);	        
	        int expectedKeyLength = PROVIDER_PUBLIC_KEY.Length / 2;
	        Assert.AreEqual(expectedKeyLength, dnsStamp.PublicKey.Length);	        
	        byte[] expectedPublicKeyBytes = ConvertHexStringToBytes(PROVIDER_PUBLIC_KEY);
	        Assert.AreEqual(expectedPublicKeyBytes, dnsStamp.PublicKey);
        }
        
        /// <summary>
        /// Converts a hex string to a byte array
        /// </summary>
        /// <param name="hexString">The hex string to convert</param>
        /// <returns>Byte array representation of the hex string</returns>
        private static byte[] ConvertHexStringToBytes(string hexString)
        {
	        return Enumerable.Range(0, hexString.Length / 2)
		        .Select(i => Convert.ToByte(hexString.Substring(i * 2, 2), 16))
		        .ToArray();
        }

		[Test]
        public void TestParseValidNonSDNS()
        {
	        DnsStamp dnsStamp = DnsUtils.ParseDnsStamp(VALID_DNS_ADDRESS);
	        Assert.IsNotNull(dnsStamp);
	        Assert.IsFalse(dnsStamp.Properties.HasValue);
			Assert.IsNull(dnsStamp.ProviderName);
	        Assert.IsNull(dnsStamp.DoHPath);
	        Assert.AreEqual(0, dnsStamp.Hashes.Count);
	        Assert.IsNull(dnsStamp.PublicKey);
	        Assert.AreEqual(AGDnsApi.ag_stamp_proto_type.PLAIN, dnsStamp.ProtoType);
	        Assert.AreEqual(VALID_DNS_ADDRESS, dnsStamp.PrettierUrl);
	        Assert.AreEqual(VALID_DNS_ADDRESS, dnsStamp.PrettierUrl);
	        Assert.AreEqual(VALID_DNS_ADDRESS + ":0", dnsStamp.ServerAddress);
	        Assert.IsFalse(dnsStamp.Properties.HasValue);
			string dnsStampString = dnsStamp.ToString();
	        Assert.AreEqual(VALID_DNS_ADDRESS, dnsStampString);
        }
	}
}