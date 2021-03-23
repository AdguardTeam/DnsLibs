using Adguard.Dns.Api;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Tests.Helpers;
using NUnit.Framework;

namespace Adguard.Dns.Tests.TestApi
{
    [TestFixture]
    public class TestDnsUtils
    {
        private const string VALID_DNS_STAMP_STR = "sdns://AgcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5AtleGFtcGxlLmNvbQovZG5zLXF1ZXJ5";
        private const string VALID_DNS_STAMP_STR_1 = "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20";
        private const string INVALID_DNS_STAMP_STR = "sdns://abcdefgh";

        [Test]
        public void TestParseValidDnsStamp()
        {
            DnsStamp dnsStamp = DnsApi.Instance.ParseDnsStamp(VALID_DNS_STAMP_STR);
            Assert.IsNotNull(dnsStamp);
            Assert.AreEqual("127.0.0.1:443", dnsStamp.ServerAddress);
            Assert.AreEqual("example.com", dnsStamp.ProviderName);
            Assert.IsNull(dnsStamp.PublicKey);
            Assert.AreEqual(1, dnsStamp.Hashes.Count);
            Assert.AreEqual(
                AGDnsApi.ag_server_informal_properties.AGSIP_DNSSEC |
                AGDnsApi.ag_server_informal_properties.AGSIP_NO_LOG |
                AGDnsApi.ag_server_informal_properties.AGSIP_NO_FILTER, dnsStamp.Properties);
            Assert.AreEqual("/dns-query", dnsStamp.DoHPath);
            Assert.AreEqual("127.0.0.1:443", dnsStamp.ServerAddress);
            Assert.AreEqual(AGDnsApi.ag_stamp_proto_type.DOH, dnsStamp.ProtoType);
            Assert.AreEqual("127.0.0.1:443", dnsStamp.ServerAddress);

            dnsStamp = DnsApi.Instance.ParseDnsStamp(VALID_DNS_STAMP_STR_1);
            Assert.IsNotNull(dnsStamp);
            Assert.IsNotNull(dnsStamp.PublicKey);
            Assert.AreEqual(32, dnsStamp.PublicKey.Length);
        }

        [Test]
        public void TestParseInvalidDnsStamp()
        {
            DnsStamp dnsStamp = DnsApi.Instance.ParseDnsStamp(INVALID_DNS_STAMP_STR);
            Assert.IsNull(dnsStamp);
        }

        [Test]
        public void TestValidUpstream()
        {
            UpstreamOptions upstreamOptions = ConfigurationHelper.CreateUpstreamOptions();
            bool result = DnsApi.Instance.TestUpstream(upstreamOptions);
            Assert.IsTrue(result);
        }

        [Test]
        public void TestInvalidUpstream()
        {
            UpstreamOptions upstreamOptions = ConfigurationHelper.CreateUpstreamOptions();
            upstreamOptions.Address = "huemoe";
            bool result = DnsApi.Instance.TestUpstream(upstreamOptions);
            Assert.IsFalse(result);
        }
    }
}